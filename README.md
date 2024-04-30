Vftable data type definition from selection Ghidra extension.

### Build

```bash
$ export GHIDRA_INSTALL_DIR=<ghidra-dir>
$ gradle buildExtension
```

### Install

Install extension : `File` > `Install Extensions` > `+` > `./dist/VFTableSel.zip`. Restart Ghidra.

Enable plugin : From Code browser tool : `File` > `Configure` > `Miscellaneous` > check `VFSelPlugin`.

### Usage

In data view, select virtual table range, right-click > `Data` > `Create vftable..`.



