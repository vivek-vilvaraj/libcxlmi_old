# libcxlmi

CXL Management Interface library (libcxlmi).

CXL Management Interface utility library, which provides type definitions
for CXL specification structures, enumerations and helper functions to
construct, send and decode commands and payloads over an out-of-band
link, typically MCTP-based CCIs over I2C or VDM. As such, target users
will mostly be BMC and/or firmware.

API
===
`struct cxlmi_ctx`: library context object.

`struct cxlmi_endpoint`: an MI endpoint - mechanism of communication with a
CXL-MI subsystem. For MCTP, an endpoint will be the component that
holds the MCTP address (EID), and receives request messages.

Requirements
============
1. Linux kernel v5.1+ for mctp/i2c support

2. Enabling use of aspeed-i2c with ACPI **out-of-tree** series
   https://lore.kernel.org/all/20230531100600.13543-1-Jonathan.Cameron@huawei.com/

3. The following kernel configuration enabled:
   ```
   CONFIG_MCTP_TRANSPORT_I2C=y
   CONFIG_MCTP=y
   CONFIG_MCTP_FLOWS=y
   CONFIG_I2C_ASPEED=y
   ```

For more info, refer to https://gitlab.com/jic23/cxl-fmapi-tests

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
```
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
