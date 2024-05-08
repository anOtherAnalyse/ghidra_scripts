Vftable data type definition from selection Ghidra extension.

### Build (Linux)

```bash
$ export GHIDRA_INSTALL_DIR=<ghidra-dir>
$ gradle buildExtension
```

### Build (Windows)

```
> gradle -PGHIDRA_INSTALL_DIR="<ghidra-dir" buildExtension
```

### Install

Install extension : `File` > `Install Extensions` > `+` > `./dist/VFTableSel.zip`. Restart Ghidra.

Enable plugin : From Code browser tool : `File` > `Configure` > `Miscellaneous` > check `VFSelPlugin`.

### Usage

In data view, select virtual table range, right-click > `Data` > `Create vftable..`.



