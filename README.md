This implements the https://github.com/kermit4/pejovu protocol.

This will make available any files in the directory ./pejovu  It will ignore any requests for anything that's not a sha256, so as long as Rust's JSON parser (Serde) doesn't have an exploit, it seems safe to leave running.

It currently assumes the filenames are their sha256 (maybe link them to their ordinary names for now)

For testing I have made available, on SSD and 200Mbps in Southern Europe,
faabcf33ae53976d2b8207a001ff32f4e5daae013505ac7188c9ea63988f8328 *ubuntu-24.04.3-desktop-amd64.iso
c3514bf0056180d09376462a7a1b4f213c1d6e8ea67fae5c25099c6fd3d8274b *ubuntu-24.04.3-live-server-amd64.iso
c74833a55e525b1e99e1541509c566bb3e32bdb53bf27ea3347174364a57f47c *ubuntu-24.04.3-wsl-amd64.wsl
their hashes are also at https://releases.ubuntu.com/noble/SHA256SUMS

as other people get copies, you should see speeds improve.  Put some of these up https://publicdomainmovie.net/ maybe.

This is very early in development, so people can send you files you didn't request, or sabotage transfers by sending invalid data.  Contributors are welcome. 

To request a file, run with the sha256 as an arguement.  It will be placed in ./pejovu/incomplete/<sha256> until it is complete.

File sharing is a primitive example common use case, not the only intended purpose.

# TODO
- save peer list 
- chose random port on first run, but then stick with it on restarts
- save transfer state to resume transfers if the application is restarted
- cookies so its not used for a DDOS, as people can spoof their source IPs
- need sub-hashes otherwise a bad bit may copy aroundd and the file may never complete anywhere


cookie as its own message.  be sure to call part timestamp too  so people dont cache it

timer to say hey and ask whatsup


