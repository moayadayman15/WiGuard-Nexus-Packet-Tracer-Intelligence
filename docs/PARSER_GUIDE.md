# Parser Guide

The v5.16 professional layer introduces a parser registry in `wiguard.services.professional_pipeline`.

## Parser contract

Each parser follows this interface:

- `can_parse(file_path)`
- `parse(file_path)`
- `validate(raw_data)`
- `extract_entities(raw_data, source_file)`
- `normalize(entities)`

## Built-in parsers

- `JsonParser`
- `XmlParser` using `defusedxml`
- `CsvParser`
- `TextConfigParser`
- `PacketTracerNativeParser` hook

## Adding a parser

Create a class extending `BaseParser`, define `extensions`, and register it with `ParserRegistry().register(MyParser())`. Parsers must return normalized entities and should never execute imported data.
