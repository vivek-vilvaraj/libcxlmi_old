# libcxlmi

CXL Management Interface library (libcxlmi).

CXL Management Interface utility library, which provides type definitions
for CXL specification structures, enumerations and helper functions to
construct, send and decode commands (CCI) and payloads over an out-of-band
(OoB) link, typically MCTP-based CCIs over I2C or VDM. As such, users will
mostly be BMC and/or firmware, targeting: Type3 SLD, Type3 MLD (FM owned)
or a CXL Switch.

CXL Manageability Model defines a CXL device to be the managed entity,
governed by *sensors* and *effectors* (command) capabilities, depending
on whether the it affects device state (read-only) or not. These can be
accessed either in-band or out-of-band. As such, CXL supports various
management interfaces and interconnects.

Actual management of CXL components is done through the Component Command
Interface (CCI), which represents a command, and can be either Mailbox
Registers or MCTP-based.

Keeping in mind the lack of safety provided by the in-band (OS driver)
equivalent, benefits for OoB management include:
- Single development environment (BMC).
- Works on any host OS.
- Does not require an OS (pre-boot).

Abstractions (opaque data structures)
-------------------------------------
- `struct cxlmi_ctx`: library context object - holds general information
common to all opened/tracked endpoints as well as library settings. Before
discovery a new context must be created via `cxlmi_new_ctx()`, providing
basic logging information. And once finished with it, the `cxlmi_free_ctx()`
counterpart must be called.

- `struct cxlmi_endpoint`: an MI endpoint - mechanism of communication with
a CXL-MI. For MCTP, an endpoint will be the component that holds
the MCTP address (EID), and receives request messages. Endpoint creation
is done by opening an MCTP endpoint through `cxlmi_open_mctp()`. The respective
housekeeping is done with the `cxlmi_close()` counterpart. Given a context,
all tracked endpoints in the system can be reached with the (and related)
`cxlmi_for_each_endpoint()` iterator.

Component discovery
-------------------
- Single, specific `nid:eid` endpoint by using `cxlmi_open_mctp()`. This will
  setup the path for CCI commands to be sent. By default, it will also probe
  the endpoint to get the CXL component this belongs to: either a Switch or a
  Type3 device. This auto-probing can by disabled with `cxlmi_set_probe_enabled()`
  or with the `$LIBNVME_PROBE_ENABLED` environment variable.

- Enumerate all endpoints with`cxlmi_scan_mctp()` (scan dbus: TODO).

Issuing CCI commands
--------------------
Once an endpoint is open, commands may be sent to the CXL device, for which
response timeouts are configurable through `cxlmi_endpoint_set_timeout()`,
taking into account any maximum values defined by the transport. For example,
for MCTP-based that is 2 seconds.

API is very command-specific (as in payloads defined in the CXL specification),
and the user is expected to know what to look for in the stack-allocated input
and outputs. This is similar to how the libnvme counterpart works. The nature
of the API depends on the input and output payload characteristics of each
command, as exemplified below. Commands take the prefix prefix `cxlmi_cmd_`.

1. Input-only payload

   ```
   struct cxlmi_cci_set_timestamp ts = {
	  .timestamp = 946684800, /* Jan 1, 2000 */
   };

   rc = cxlmi_cmd_set_timestamp(ep, &ts);
   if (rc) {
	   /* handle error */
   }
   ```

2. Output-only payload

   ```
   struct cxlmi_cci_get_timestamp ts;

   rc = cxlmi_cmd_get_timestamp(ep, &ts);
   if (rc == 0) {
	   /* do something with ts.timestamp */
   }
   ```

3. Input and output payloads

   ```
   struct cxlmi_cci_get_log_req in = {
	   .offset = 0,
	   .length = cel_size;
	   .uuid = cel_uuid;
   } ;
   struct cxlmi_cci_get_log_rsp ret;

   rc = cxlmi_cmd_get_log(ep, &in, &ret);
   if (rc == 0) {
	   /* do something with ret. */
   }
   ```

4. No input, no output payload

   ```
   rc = cxlmi_cmd_request_bg_operation_abort(ep);
   if (rc) {
	   /* handle error */
   }
   ```

When sending a command to a device, a return of `0` indicates success.
Otherwise `-1` is returned to indicate a problem sending the command, while
`> 0` corresponds to the CXL defined returned code, which can be translated
to a string with `cxlmi_cmd_retcode_to_str()`. Upon error, the return payload
is undefined and should be considered invalid.

   ```
   rc = cxlmi_cmd_infostat_identify(ep, &ret);
   if (rc) {
	   if (rc > 0)
		   fprintf(stderr, "%s", cxlmi_cmd_retcode_to_str(rc));
	   return rc;
   }
   ```

Logging
-------
Library internal logging information is set upon context creation, using `stderr`
by default. Logging levels are standard `syslog`.

Considerations
--------------
A few considerations users should keep in mind when evaluating using this library:

- APIs are influenced by libnvme.

- The library leaves any and all serialization up to the user - libs should not
hold locks.

- This library masks many of the protections provided by the OS driver, as such,
users must provide the correct command(s) to the correct CXL Component. Similarly
device state may be altered, and therefore users get to keep the pieces.

- Commands initiated on MCTP-based CCIs are not tracked across any component state
change, such as Conventional Resets.

- CXL r3.1 + DMTF binding specs are not clear on what Message type is used for the
generic command set - these can be issued to either a switch or a type 3 device.
The assumption here is that for those command either smctp_type is fine.

- FMAPI command set (used to manage/tunnel CXL Switches) is TODO.

Requirements
============
1. arm64 or x86-64 architecture.

2. Linux kernel v5.15+ for MCTP support (as well as header files).

3. Enabling use of aspeed-i2c with ACPI **out-of-tree** series
   https://lore.kernel.org/all/20230531100600.13543-1-Jonathan.Cameron@huawei.com/

4. The following kernel configuration enabled:
   ```
   CONFIG_CXL_MEM_RAW_COMMANDS=y
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

Programs making use of this library must include the `libcxlmi.h` header file
and link with `-lcxlmi`.

References
==========
- This library has been influenced by cxl-fmapi-tests, libnvme and libcxl (ndctl).
- CXL 3.1 Specification.
- CXL Type3 Device Component Command Interface over MCTP Binding Specification (DSP0281).
- CXL Fabric Manager API over MCTP Binding Specification (DSP0324).
