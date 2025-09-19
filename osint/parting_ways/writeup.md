OSINT CTF Writeup — Parting Ways ChallThe riddle text provides several important hints:

- "ancient kingdom of the Teutons" → refers to Germany
- "fortress with 71 noble houses" → Kelheim is known for its historical fortress
- "two brothers parting ways, dividing into three branches" → This points to the rivers Danube and Altmühl, which meet near Kelheim, and the Danube's branching channels

This geographic description fits perfectly with Kelheim's location.

## Step 5: Flag ConstructionChallenge Overview

We were given the following riddle:

"In the ancient kingdom of the Teutons there was a fortress with 71 noble houses… two brothers… three branches form a bridge… Where did the two brothers part ways?"

We also had two pictures:
- A scenic photo of a river bend with a small town
- A cropped version focused on the town

Flag format: CTF{town_name}

## Step 1: Image Analysis

The picture shows:
- A river making a bend
- A sandy beach-like area on the inside of the bend
- A small town with red-roof houses
- Photo is taken from a wooded hillside above the town

This appeared to be a European riverside town.

## Step 2: Reverse Image Search

To identify the location, I used Google Image Search:
- I cropped the picture to focus on the town and river bend, removing the trees
- This makes the search engine concentrate on the unique geography and houses, not just the forest

## Step 3: Search Results

The search results matched with photos of Kelheim, a town in Bavaria, Germany.

One result showed Ferienhaus Andadoana, Kelheim with the same river bend and town layout visible in the CTF image, confirming the location.

## Step 4: Connecting the Clues

The riddle text mentions:

"ancient kingdom of the Teutons" → refers to Germany.

"fortress with 71 noble houses" → Kelheim is known for its old fortress history.

"two brothers parting ways, dividing into three branches" → This points to the rivers Danube and Altmühl, which meet near Kelheim, and the Danube’s branching channels.

This fits perfectly with the geography of Kelheim.

🏆 Step 5 — Build the Flag

Following the required flag format:
CTF{Kelheim}

## Solution

Flag: CTF{Kelheim}