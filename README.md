<!-- markdownlint-disable MD007 MD012 MD033 -->

# @steveglenner/tplink-smarthome-api

Fork of [plasticrake/tplink-smarthome-api](https://github.com/plasticrake/tplink-smarthome-api) with KLAP v1/v2 support for firmware that closed TCP 9999 (for example KL125 1.1.1).

[![NPM Version](https://img.shields.io/npm/v/@steveglenner/tplink-smarthome-api.svg)](https://www.npmjs.com/package/@steveglenner/tplink-smarthome-api)

TP-Link Smarthome API

**[Changelog](CHANGELOG.md)**

## Known Supported Devices

| Model                                                                                                    | Type               |
| -------------------------------------------------------------------------------------------------------- | ------------------ |
| HS100, HS103, HS105, HS107, HS110,<br/>HS200, HS210, HS220, HS300, KP303, KP400<br/>ES20M, EP40, ...etc. | Plug               |
| LB100, LB110, LB120, LB130, LB200, LB230, KL50, KL120, KL125<br/>...etc.                                 | Bulb               |
| KL430<br/>...etc.                                                                                        | Bulb (light strip) |

Many other TP-Link Plug and Bulb models may work as well. Note that Tapo devices are not supported.

## Related Projects

- [TP-Link Smarthome Device Simulator](https://github.com/plasticrake/tplink-smarthome-simulator) - Useful for automated testing
- [TP-Link Smarthome Crypto](https://github.com/plasticrake/tplink-smarthome-crypto)
- [TP-Link Smarthome Homebridge Plugin (original)](https://github.com/plasticrake/homebridge-tplink-smarthome)
- [homebridge-tplink-smarthome-klap2](https://github.com/scratchdiver/homebridge-tplink-smarthome-klap2) - this fork's Homebridge plugin

## Examples

See more [examples](examples).

```javascript
const { Client } = require('@steveglenner/tplink-smarthome-api');

const client = new Client({
  defaultSendOptions: { timeout: 15000 },
  // Required for KLAP firmware (Kasa email/password):
  // username: 'you@example.com',
  // password: 'your-kasa-password',
});
const plug = client.getDevice({ host: '10.0.1.2' }).then((device) => {
  device.getSysInfo().then(console.log);
  device.setPowerState(true);
});

// Look for devices, log to console, and turn them on
client.startDiscovery().on('device-new', (device) => {
  device.getSysInfo().then(console.log);
  device.setPowerState(true);
});
```

## CLI

Install the command line utility with `npm install -g @steveglenner/tplink-smarthome-api`. Run `tplink-smarthome-api --help` for help.

Pass `--username` and `--password` (Kasa account) when talking to devices that use KLAP.

## API

[API docs can be found here.](https://plasticrake.github.io/tplink-smarthome-api/)

For functions that send commands, the last argument is `SendOptions` where you can set the `transport` ('tcp','udp') and `timeout`, etc.

Functions that take more than 3 arguments are passed a single options object as the first argument (and if its a network command, SendOptions as the second.)

## Credits

Thanks to George Georgovassilis and Thomas Baust for [figuring out the HS1XX encryption](https://blog.georgovassilis.com/2016/05/07/controlling-the-tp-link-hs100-wi-fi-smart-plug/).

Some design cues for Client based on [node-lifx](https://github.com/MariusRumpf/node-lifx/)
