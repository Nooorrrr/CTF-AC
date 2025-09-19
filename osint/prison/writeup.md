OSINT CTF Writeup — Minecraft Prison Challenge

Challenge Recap

We were given:

"You're going to prison kid. There's no way around that. Take a good look and learn your betters..."

And a screenshot of a Minecraft server prison spawn area.
We also had a flag format:

If we can join the server and find coordinates:
CTF{server_host(ChunkX,ChunkY,ChunkZ)}

If we can’t join the server:
CTF{server_host:owner_username}

Example:
CTF{mc.hypixel.net:hypixel}

Step 1 — Look Carefully at the Image

In the screenshot we see:

Ranks & usernames like:

WARDEN PsyChN0delic

SBUARD ButterInc

SBUARD Cheesa

GUARD Dragon

CHIEF WARDEN Leaky... (cut off in the image)

A sign says:
"Learn about how to apply on our /discord"

This looks like the staff board in a Minecraft prison server.

Step 2 — Google the Staff Names

Searching names like "PsyChN0delic minecraft prison" or "ButterInc Cheesa prison" quickly leads to server listings and discussions about a Minecraft prison server called The Pen.

Step 3 — Find the Server Host

On public Minecraft server listing sites, “The Pen” appears with the IP:

play.thepen-mc.net


That matches the server_host part we need.

Step 4 — Identify the Owner

From the staff wall, the top rank on the right is CHIEF WARDEN Leaky....
Searching “The Pen minecraft Leaky” shows the full username:
Leaky_Tandos (listed as the server’s owner/admin on multiple forums).

Step 5 — Build the Flag

Since we don’t have in-game access to coordinates, we use the owner username format:

CTF{play.thepen-mc.net:Leaky_Tandos}

Final Answer

Flag:
CTF{play.thepen-mc.net:Leaky_Tandos}

Key OSINT Skills Used

Visual clues from the screenshot (names, titles, Discord mention).

Search engine queries combining names with “minecraft prison server.”

Server listing websites to confirm the host/IP.

Forum digging to reveal the full owner username.