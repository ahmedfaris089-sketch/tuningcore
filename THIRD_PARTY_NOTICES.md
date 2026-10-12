# Third-party notices

`core/importers/kp_binary.py` reads WinOLS .kp map packs using a record layout adapted from
[TracqiTechnology/MxT](https://github.com/TracqiTechnology/MxT) (`KpHintParser.kt`), licensed under the
Apache License 2.0, by way of the AKTOOL local backend's `kp.py`. A copy of that license is in
`licenses/Apache-2.0.txt`. Changes: axis element size and the signed flag are read from the record,
implausible decodes are reported instead of kept, and maps are passed to the OLS importer.

WinOLS and the KP format belong to their respective owners. This read-only parser is not affiliated with EVC.
