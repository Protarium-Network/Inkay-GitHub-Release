<h1 align="center">Inkay - Aroma patches for Protarium</h1>

<p align="center">
  <a href="https://www.gnu.org/licenses/gpl-3.0"><img src="https://img.shields.io/badge/License-GPLv3-blue.svg" alt="License: GPL v3"></a>
  <img src="https://img.shields.io/badge/Status-In%20Development-orange?style=flat-square" alt="Status">
</p>

![Protarium network logo](https://i.imgur.com/wgSRoyq.jpeg)

<p align="center">
  <b>Inkay is an Aroma/WUPS plugin that patches various Nintendo Network URLs on a Wii U to use Protarium Network instead. It also (for the time being) bypasses SSL verification in most cases. It redirects Nintendo Network in:</b>
</p>

- IOSU-side connections (Friends, SpotPass, accounts etc.)
- Account Settings
- NNCS
- Nintendo eShop
- Miiverse (in-game)
- Miiverse applet
- Demaecan
- Just Dance 2015-2019
- Lost Reavers
- Need for Speed Most Wanted U
Inkay also includes game-specific patches to add extra features:
- Modpack-specific matchmaking for global, regional rooms (by simulating extra DLC) - **Mario Kart 8**
- P2P port override for better connection stability (if you port forward) - **Minecraft: Wii U Edition**, **Mario Kart 8**, **Splatoon**
- 100 Mario Challenge pickup-service redirection - **Super Mario Maker**
- Demonware service redirection - **Call of Duty: Black Ops II** + **Call of Duty: Ghosts**

## Requirements
Inkay is only supported on the release version of Aroma configured for autoboot/coldboot. Other configurations (specifically lacking coldboot) may cause issues with SpotPass.

## Installation - If you had pretendo before:
- Grab the latest release from [here](https://github.com/Protarium-Network/Inkay-GitHub-Release/releases) and download the premade wiiu.zip.
- Insert your SDcard from your Wii U into your PC.
- Drag and drop the wiiu folder from the zip inside on your SDcard.

## Installation (If you've never used pretendo or Aroma before)
- Follow the Aroma install guide [here](https://wiiu.hacks.guide/)
- Grab the latest release from [here](https://github.com/Protarium-Network/Inkay-GitHub-Release/releases) and download the premade wiiu.zip.
- Insert your SDcard from your Wii U into your PC.
- Drag and drop the wiiu folder from the zip inside on your SDcard.

- All done! If you encounter any issues join the discord server [here](https://discord.gg/h5XSJtRnfZ)

## Safety
Inkay's patches are all temporary, and only applied in-memory without modifying your console. The SSL patch, while also temporary, could reduce the overall security of your console while active - this is because it no longer checks if a server is verified. However, this does not apply to the Internet Browser, where SSL still works as expected.

## Build
### Compiling with Docker
Inkay's dependencies and build tooling can be handled as a container, which is recommended for WUPS plugins. Using `docker` or `podman`:
```shell
docker build -t inkay .
docker run --rm -v $(pwd):/app inkay make
# you can replace "make" with other commands - e.g. make clean
```
If using `podman` on SELinux systems (like Fedora Linux), you might need to use `$(pwd):/app:Z` instead of `$(pwd):/app`.
### Compiling with DevkitPro
Inkay has the following dependencies aside from devkitPPC and wut:
- [WiiUPluginSystem](https://github.com/wiiu-env/WiiUPluginSystem)
- [WiiUModuleSystem](https://github.com/wiiu-env/WiiUModuleSystem)
- [libmocha](https://github.com/wiiu-env/libmocha)
- [libkernel](https://github.com/wiiu-env/libkernel/)
- [libnotifications](https://github.com/wiiu-env/libnotifications/)
- [libfunctionpatcher](https://github.com/wiiu-env/libfunctionpatcher)

Each of these should be `make install`-able. 
After that, run `make` if you are on Windows, or `.\build.sh` if you are on Linux.

## TODO
See [Issues](https://github.com/Protarium-Network/Inkay-GitHub-Release/issues).

## License & Copyright
This project is licensed under GPLv3.0. 
Copyright © 2026 Protarium Network.
