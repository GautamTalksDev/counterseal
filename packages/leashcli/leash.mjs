#!/usr/bin/env node
// leashcli is the Counterseal CLI's first name. This package only runs the counterseal package (the same CLI, zero
// dependencies of its own) so that `npx leashcli ...`, configured agents and MCP configs keep working after the rename.
import 'counterseal/leash.mjs';
