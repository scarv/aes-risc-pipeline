
# RISC-V Crypto RTL

*Notes on the experimental RTL for implementing proposed instructions.*

---

This directory contains *experimental* Verilog RTL implementing proposed
RISC-V AES ISE instructions.

Each sub-directory implements a particular (class of) instruction(s).

The top level makefile contains macros useful for building simple
synthesis and simulation targets. Each sub-makefile it includes is
then responsible for adding the sensible targets for each instruction.

## Getting Started

You will need Yosys installed for these flows to work.

- Make sure you have run the project workspace setup script:

  ```sh
  $> source bin/conf.sh
  $> cd $REPO_HOME/rtl
  ```

- To list the available synthesis targets:
  ```sh
  $> make print-synth-targets
  ```
  
  All of which can be run in one go with:
  ```sh
  $> make synth-all
  ```

  Again, all of these can be run with:
  ```sh
  $> make sim-all
  ```

- The results of synthesis and simulation runs are placed in
 `$REPO_BUILD/rtl/*`.

