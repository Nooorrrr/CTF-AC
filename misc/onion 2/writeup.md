## Solution : 
I've analyzed the image with stego tools til I found this adress with the help of zsteg : ```t465kjcwuqbpabjeh3za73zkxxlzymattskj2gj3ftkvmm5unnyqrvyd.onion```, Ive also find some other encrypted strings but after decrypting them they seemed the same as this given adress. I visited the adress and found that it refers to a Snowden quote, did inspect elemnt and found the font file, when I used Strings on it, I found this long base64 string.      
So i went to cybercheff and applied those filters : ``` from base64, from hex, from morse, from binary```      

<img width="1528" height="756" alt="image" src="https://github.com/user-attachments/assets/e410967d-1a4b-4088-9d21-f8ef29cfdae5" />

and it revield to me this location : ```https://www.google.com/maps/place/ARChA/@45.7450165,21.225122,17z/data=!4m16!1m9!3m8!1s0x47455d9b87725af1:0x7a82191592d97493!2sARChA!8m2!3d45.7450165!4d21.2277023!9m1!1b1!16s%2Fg%2F11vbtv2ys4!3m5!1s0x47455d9b87725af1:0x7a82191592d97493!8m2!3d45.7450165!4d21.2277023!16s%2Fg%2F11vbtv2ys4?entry=ttu&g_ep=EgoyMDI1MDkxMC4wIKXMDSoASAFQAw%3D%3D``` where i scanned the qr code for the flag     

<img width="1113" height="344" alt="image" src="https://github.com/user-attachments/assets/04a50d2c-8e97-4cd0-b5fa-e4a96172e256" />
