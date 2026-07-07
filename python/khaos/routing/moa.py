"""Mixture-of-Agents (MoA): proposers draft, an aggregator synthesizes.

The pipeline runs N proposer models concurrently over the same prompt, collects
their answers, then asks an aggregator model to produce a single synthesized
response. Routing to each model is delegated to a caller the router supplies,
so this module stays free of provider/transport details and is straightforward
to unit-test with fakes.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import AsyncIterator, Callable, Awaitable

import yaml

from khaos.agent.core import Message

logger = logging.getLogger(__name__)

# A caller streams a model's response for the given messages. The router
# supplies one backed by its provider manager; tests supply fakes.
ModelCaller = Callable[[str, list[Message]], "AsyncIterator[Message]"]


@dataclass(frozen=True)
class MoAPipeline:
    """One proposer + aggregator pipeline definition."""

    name: str
    proposers: list[str]
    aggregator: str
    rounds: int = 1


@dataclass
class MoAConfig:
    """Top-level MoA configuration parsed from config.yaml."""

    enabled: bool = False
    pipelines: list[MoAPipeline] = field(default_factory=list)

    @classmethod
    def from_config(cls, config: dict | None) -> "MoAConfig":
        """Build a MoAConfig from a parsed config.yaml mapping.

        Reads the ``models.moa`` section. Unknown shapes fall back to disabled,
        so a config without MoA never breaks the router.
        """
        if not config:
            return cls()
        models = config.get("models") if isinstance(config, dict) else None
        if not isinstance(models, dict):
            return cls()
        moa = models.get("moa")
        if not isinstance(moa, dict):
            return cls()
        enabled = bool(moa.get("enabled", False))
        pipelines: list[MoAPipeline] = []
        for raw in moa.get("pipelines") or []:
            if not isinstance(raw, dict):
                continue
            proposers = list(raw.get("proposers") or [])
            aggregator = raw.get("aggregator")
            if not proposers or not aggregator:
                continue
            pipelines.append(
                MoAPipeline(
                    name=str(raw.get("name", f"{aggregator}")),
                    proposers=[str(p) for p in proposers],
                    aggregator=str(aggregator),
                    rounds=int(raw.get("rounds", 1)),
                )
            )
        return cls(enabled=enabled, pipelines=pipelines)

    @classmethod
    def from_yaml_file(cls, path) -> "MoAConfig":
        """Load from a YAML file path, returning disabled on any error."""
        try:
            data = yaml.safe_load(open(path, encoding="utf-8"))  # noqa: SIM115
        except (OSError, yaml.YAMLError):
            return cls()
        return cls.from_config(data if isinstance(data, dict) else {})

    def pipeline(self, name: str | None = None) -> MoAPipeline | None:
        """Return the named pipeline, or the first one when name is None."""
        if not self.pipelines:
            return None
        if name is None:
            return self.pipelines[0]
        for pipeline in self.pipelines:
            if pipeline.name == name:
                return pipeline
        return None


class MoARunner:
    """Execute a MoA pipeline against a model caller."""

    def __init__(self, caller: ModelCaller):
        self.caller = caller

    async def run(
        self,
        pipeline: MoAPipeline,
        messages: list[Message],
    ) -> AsyncIterator[Message]:
        """Run one pipeline: gather proposers, then stream the aggregator.

        Proposers run concurrently; their outputs are concatenated into the
        aggregator prompt. The aggregator streams the final answer token by
        token. Multiple rounds (if configured) feed the aggregator's own output
        back as a fresh proposer in the next round.
        """
        if not pipeline.proposers:
            raise ValueError(f"MoA pipeline {pipeline.name!r} has no proposers")
        if not pipeline.aggregator:
            raise ValueError(f"MoA pipeline {pipeline.name!r} has no aggregator")

        current_messages = list(messages)
        for round_index in range(max(1, pipeline.rounds)):
            proposals = await self._gather_proposals(pipeline, current_messages)
            aggregator_prompt = self._build_aggregator_prompt(
                pipeline, proposals, current_messages
            )
            final_seen = round_index == pipeline.rounds - 1
            aggregator_output: list[str] = []
            async for chunk in self.caller(pipeline.aggregator, aggregator_prompt):
                if chunk.content:
                    aggregator_output.append(chunk.content)
                    if final_seen:
                        yield chunk
                if final_seen and chunk.stop_reason:
                    yield chunk
            if not final_seen:
                # Feed the aggregator's synthesized answer back as context for
                # the next round's proposers.
                current_messages = aggregator_prompt + [
                    Message(role="assistant", content="".join(aggregator_output))
                ]

    async def _gather_proposals(
        self, pipeline: MoAPipeline, messages: list[Message]
    ) -> list[str]:
        """Call all proposers concurrently and return their textual outputs."""
        tasks = [self._collect_proposal(model, messages) for model in pipeline.proposers]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        proposals: list[str] = []
        for model, result in zip(pipeline.proposers, results):
            if isinstance(result, Exception):
                logger.warning("MoA proposer %s failed: %s", model, result)
                continue
            if result:
                proposals.append(result)
        return proposals

    async def _collect_proposal(self, model: str, messages: list[Message]) -> str:
        parts: list[str] = []
        async for chunk in self.caller(model, messages):
            if chunk.content:
                parts.append(chunk.content)
        return "".join(parts)

    @staticmethod
    def _build_aggregator_prompt(
        pipeline: MoAPipeline,
        proposals: list[str],
        original_messages: list[Message],
    ) -> list[Message]:
        """Compose the aggregator prompt from proposals + original context."""
        if not proposals:
            return original_messages
        numbered = "\n\n".join(
            f"## Proposal {i + 1}\n{proposal}" for i, proposal in enumerate(proposals)
        )
        synthesis_instruction = (
            "You are aggregating multiple model proposals into one final answer. "
            "Reconcile disagreements, keep the strongest points, and drop "
            "redundancy. Do not invent facts not supported by the proposals.\n\n"
            f"{numbered}"
        )
        return original_messages + [
            Message(role="user", content=synthesis_instruction)
        ]


__all__ = ["MoAPipeline", "MoAConfig", "MoARunner", "ModelCaller"]
