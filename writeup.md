# OSINT

## Cornfield Chase
![zen_BAk9VHcnxt](https://github.com/user-attachments/assets/288d4001-48f9-453b-87ca-0b7129c460e7)

- The image had many clues, but the most significant was the blue sign
- It had chinese written on it with some unique codes
- I reverse searched the image and turns out it is used by Taiwan power supply
- So I went to their [website](https://data.gov.tw/en/datasets/33305) and download a csv and searched up that got
- I got some proprietary taiwan coordinates which I converted to DMS
- Then I went to that location and looked around for some time and found the exact location



## Bonsai Bankai
![zen_kMfKQtQtmB](https://github.com/user-attachments/assets/f069b871-20da-43e7-ad0f-a7139557c5bf)

- The area was obviously in Japan cause of the house structures and signs with japenese around
- I looked around and thought about reverse image searching the brows house
- I found a property seller who had address attatched to this house
- This gave me the exact coords
- I went to that spot and got the flag

## The Flash
![zen_Bb16cvZ7dg](https://github.com/user-attachments/assets/74414706-1b57-48b1-a0eb-12a6de258de4)

- The image burned my retina
- It barely had anything visible on it to figure out the place
- The electric pole was too generic and so where the yellow traffic signs
- Decided to reverse image search the vegetation and turns out Ooty has a similar scenary near it
- The pine forest area was the biggest hint
- I went to street view near there and realised the shape and structure of whole thing was similar
- Now the easy part was over and I spent 4-5 hours finding the exact spot
- Finally went a bit near city area and street view had this similar glare, so I followed the path till it reached near lake and pine tree forest
- After going up the hill a bit I found the exact area and got the flag
- Turns out it was just below the path I started with in ooty

## Hillbilly
![zen_V8IHrsIhMP](https://github.com/user-attachments/assets/452cd62b-331a-4190-8281-1c6c3842d306)

- First I tried searching for trees and turns out olive trees are common around Greece, Italy and Syria area
- The best bet for me was Greece as it has lot of area with similar olive groves
- At first I thought it was near Athens and 2 cities near it, I spent around 8 hours in this area
- Then I decided to use a filter tool for google street view before 2016, as the watermark on challenge image was 2015
- Now I scanned almost 3 cities and went around and around, the mountains there did look similar and so were trees
- There was no hope though so I decided to try out my last method
- I reverse image searched the grill/barrier in challenge image with olive tree in background
- After discaridng first few searches, I found a plot seller that had pictures of similar colour scheme, trees, soil and most importantly barriers on their (website)[https://www.rightmove.co.uk/properties/161713154?currencyCode=GBP#/media?id=media8&ref=photoCollage&channel=OVERSEAS]
- So I decided to go there and found exactly the same mountains
- I went near it and tried to find similar view/angle
- After few minutes I found similar looking groves and barriers
- Followed it and found same background too
- Thus I got the flag

## Road Not Taken
<img width="1950" height="1383" alt="image" src="https://github.com/user-attachments/assets/3fa368a6-9aac-43a7-911d-414d42301815" />

- At first I had no clue where this could be but after searching a while I found out only Ghana has black tape in front side of car
- Then I went there and looked for like an hour but it was too huge
- Later decided to search up and found there are metas for Ghana
- I decided to follow (plonkit)[https://www.plonkit.net/ghana] and (geotips)[https://geotips.net/africa/] for this
- Decided to follow tape meta on there which marked specific roads with similar tape wearing
- Then looked around and went to south and south eastern area as they are supposed to have a bit of red soil and are lush
- Looked there for hours but roads wouldn't end
- Decided to follow compass on challenge's page and looked through all north/south looking roads
- Spent around 5 hours on this as I decided to even check western and bit of northern region for north-south leading roads
- Turns out the compass was broken
- Now it clicked to me that it is obviously not a highway as the title says road not taken
- So I decided to check more roads, now based on clear sky, sun location and tape meta
- After 5-6 more hours I was near entrance of this city where I found same van in front of me as challenge
- I followed it and finally found the flag

---

# Web Exploitation

## Database Reincursion
- This one was quite tricky as it filtered `or` and `--` in login form
- I tried as many bypasses as I could online on cheat sheets and guides, but they were either filtered, or not recognized by this sql or straight up blocked cause of character limit
- Then I wondered if I tried SQLI in passwords field then it would work or not
- Suprisingly this worked:
```
username: admin
password: ' UNION SELECT '1', '2', '3' FROM users WHERE ''='
```
- Then I was inside it and now I was supposed to find kiwi (same as previous 2 database challenges)
- But this time there were filters
- So I tried to simply use `Kiwi' /*` which didn't trigger the filter and worked in search box for names
- I did find kiwi but there was limit of 4 rows so it didnt't include one from management
- I decided I need to specify both Kiwi and Management, so I used `Kiwi' AND department='Management' /*` , this again didn't trigger the filters
- Thus I found the management kiwi who had password in her notes: `ecSKsN7SES`
- Then I accessed the admin panel and similarly to older database challenge, we had to find actual name of redacted and thus I decided to find it using `' UNION SELECT 1, sql, 3, 4 FROM sqlite_master /*`
- Then I finally got the flag using `' UNION SELECT 1, secrets, 3, 4 FROM CITADEL_ARCHIVE_2077 /*`
