# ptrace_read_teb

A minimal example project demonstrating how to use `ptrace` to read the Thread Environment Block (TEB) of a process on Linux.  
**Note:** This example targets processes running under Wine on Linux.

## Features

- Attaches to a running process using `ptrace`
- Reads and displays TEB-related information
- Example code for low-level process introspection

## Requirements

- Linux (x86_64)
- Wine (for running Windows binaries)
- Clang
- Root privileges (for attaching to other processes)

## Building

```sh
make
```

Or compile manually:

```sh
clang -o ptrace_read_teb main.c
```

## Usage

```sh
sudo ./ptrace_read_teb <pid>
```

Replace `<pid>` with the process ID you want to inspect.  
Make sure the target process is a Windows application running under Wine.

## Disclaimer

This project is for educational and research purposes only.

## License

MIT License