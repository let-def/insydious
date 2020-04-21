Click [HERE](https://let-def.github.io/insydious) to run the unlocker.

# Story

My friend's Acer computer suddenly stopped working one day. We assume it is related to a faulty update or behavior, but in short:

1. Her Ubuntu installation could not boot (GRUB could exec the kernel but no hard drive was visible).
2. Access to the BIOS/UEFI settings were protected by password (though we did not put one).

The first problem was due to the mode used to expose the NVME controller, "AHCI" or "RST with Optane" on this Acer laptop. Linux kernel only supports "AHCI" mode. Our best guess was that the communication mode switched to RST with Optane over night.

Anyway, the whole situation did not make sense: restricted access and locked into a protocol incompatible with the only operating system installed on that laptop. Entering a wrong password three times led us to an "Unlock password" screen. Looking up internet revealed that we could recover access to BIOS/UEFI if we could get past that screen.

Contacting Acer did not help much: as Linux users we were not welcome, and there was not such thing as unlocking. We had to send them the computer and pay for service intervention. WTF moment.

On internet, I found a few resources to pass that unlock screen:

- http://bios-pw.org/ (implementing algorithms from: [pwgen-for-bios](https://github.com/bacher09/pwgen-for-bios/issues), [bios-pwgen](https://github.com/dogbert/bios-pwgen))
- [Dogbert's Blog](https://dogber1.blogspot.com/), where the author explains how he escaped some of these arbitrary restrictions (work that lead to these implementations)

Unfortunately, there was no ressources about the kind of unlocking scheme that our laptop featured ("10 digits"). Time to look at how to circumvent this lock, recover Linux interoperability... and just own our computer again (WTF).

# TL;DR

This repository contains an OCaml implementation of the lock code derivation scheme that is compiled to javascript accessible [here](https://let-def.github.io/insydious).

# Long story

Coming soon: blog post about how to reimplement the derivation scheme.
