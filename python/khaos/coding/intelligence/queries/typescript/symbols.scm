(class_declaration name: (type_identifier) @name) @definition.class
(function_declaration name: (identifier) @name) @definition.function
(method_definition name: (property_identifier) @name) @definition.method
(interface_declaration name: (type_identifier) @name) @definition.interface
(type_alias_declaration name: (type_identifier) @name) @definition.type
(enum_declaration name: (identifier) @name) @definition.enum
(internal_module name: [(identifier) (string)] @name) @definition.module
(variable_declarator name: (identifier) @name value: [(arrow_function) (function_expression)]) @definition.function
