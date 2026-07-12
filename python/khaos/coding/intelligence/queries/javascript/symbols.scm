(class_declaration name: (identifier) @name) @definition.class
(function_declaration name: (identifier) @name) @definition.function
(generator_function_declaration name: (identifier) @name) @definition.generator
(method_definition name: (property_identifier) @name) @definition.method
(variable_declarator name: (identifier) @name value: [(arrow_function) (function_expression) (generator_function)]) @definition.function
