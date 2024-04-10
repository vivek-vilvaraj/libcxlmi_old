# libcxlmi

CXL Management Interface library (libcxlmi).

CXL Management Interface utility library, which provides type definitions
for CXL specification structures, enumerations and helper functions to
construct, send and decode commands and payloads over an out-of-band
link, typically MCTP-based CCIs over I2C or VDM. As such, users will mostly
be BMC and/or firmware, targetting: Type3 SLD, Type3 MLD (FM owned) or
a Switch.

Two abstractions (opaque data structures):
- `struct cxlmi_ctx`: library context object - this holds general information
about opened/tracked endpoints as well as library settings. Before discovery,
or anything else for that matter, a new context is created via `cxlmi_new_ctx()`,

- `struct cxlmi_endpoint`: an MI endpoint - mechanism of communication with
a CXL-MI subsystem. For MCTP, an endpoint will be the component that holds
the MCTP address (EID), and receives request messages. Endpoint creation
is done by opening an mctp endpoint throught `cxlmi_open_mctp()`.

Component discovery:
- Single, specific `nid:eid` endpoint by using `cxlmi_open_mctp()`. This will
  setup the path for CCI commands to be sent. By default, it will also probe
  the endpoint to get the CXL component this belongs to: either a Switch or a
  Type3 device. This auto-probing can by disabled with `cxlmi_set_probe_enabled()`.

- Enumerate all endpoints with`cxlmi_open_scan()` (auto-scan dbus: TODO).

Sending commands:
Once an endpoint is opened, commands may be sent to the device. The provided
API is very command-specific (as in payloads defined in the CXL specification),
and the user is expected to know what to look for in the stack-allocated return
output. This is similar to how the libnvme counterpart works. Commands that are
read-only take the prefix `cxlmi_query_cci_`. For example, to get the timestamp
of the device:

   ```
   struct cxlmi_cci_get_timestamp ts;

   rc = cxlmi_query_cci_timestamp(ep, &ts);
   if (rc == 0) {
	  /* do something with ts.timestamp */
   }
   ```

Requirements
============
1. arm64 or x86-64 architecture.

2. Linux kernel v5.1+ for mctp/i2c support.

3. Enabling use of aspeed-i2c with ACPI **out-of-tree** series
   https://lore.kernel.org/all/20230531100600.13543-1-Jonathan.Cameron@huawei.com/

4. The following kernel configuration enabled:
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

Linking
=======

Programs making use of this library must include `libcxlmi.h` and link with `-lcxlmi`.

References
==========
- CXL 3.1 Specification.
- CXL Type3 Device Component Command Interface over MCTP Binding Specification (DSP0281).
- CXL Fabric Manager API over MCTP Binding Specification (DSP0324).
