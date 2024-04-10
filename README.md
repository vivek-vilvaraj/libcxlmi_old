# libcxlmi

CXL Management Interface utility library, which provides type definitions
for CXL specification structures, enumerations and helper functions to
construct, dispatch and decode commands and payloads over an out-of-band
link, typically .MCTP-based CCIs over I2C or VDM. As such, target users
will mostly be BMC and/or firmware.

Requirements
============


Build
=====
To `configure` the project as a shared library (default):

```
meson setup build;
```
Alternatively, to configure for static libraries:
```
meson setup --default-library=static build
```
Then compile it:
meson compile -C build;
```

Optionally, to install:

```
meson install -C build
```

References
==========

CXL 3.1 Specification.
CXL Type3 Device Component Command Interface over MCTP Binding Specification (DSP0281).
CXL Fabric Manager API over MCTP Binding Specification (DSP0324).