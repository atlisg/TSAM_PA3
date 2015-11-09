

Protocol
========

## Our protocol:

We decided to use a text based protocol.

All messages between server and client start with the string "xx:" where xx is a number between 00 and 18.

Parameters are seperated with a colon (":") and end-of-message is denoted by "did-dah-did-dah-did". Only joking, it's carriage return followed by linefeed ("\r\n" or "CR-LF").

Each number indicates a specific type of message shown below:

### Client Messages

| Code | Command           | Parameters       |Error reply      | Success reply | Server Action                          |
| ----:|:------------------|:-----------------|:----------------|:--------------|----------------------------------------|
| 01   | /user             |\<user\>\<password\>  | WRONGPASS, INUSE| AUTHENTICATED | Add user in Lobby and list of all users|
| 02   | /bye or /quit     |                  |                 |                |Disconnect    |                                        |
| 03   | /join             |\<room\>            |                 | JOIN          | Add user in room                       |
| 04   | /who              |\<room\>            |                 | LISTOFALLUSERS| Send the client a list of all users    |
| 05   | /list             |                  |                 | LISTOFROOMS   | Send the client a list of all rooms    |
| 06   | /say or none      |[\<user\>]\<msg\>     | NOSUCHNICK      | MSG           | Send private/public messages           |
| 07   | /game             |                  |                 |               |                                        |
| 08   | /roll             |                  |                 |               |                                        |

#### Examples

| Command | Message                | Action                                              |
| -------:|:-----------------------|:----------------------------------------------------|
| /join   | "03:VegansBtrippin\r\n"| client is taken to the room called "VegansBtrippin  |
| /who    | "05:\r\n"              | client is given a list of active users              |
| /say    | "06:Atli:Blessaður\r\n"| Atli is sent a private massage from client          |

### Server Messages

| Code | Reply             | Parameters       | Client Action                                      |
| ----:|:----------------- | -----------------|----------------------------------------------------|
| 00   | WELCOME           |\<user\>\<room\>      | Set prompt to user@room> and print welcome msg |
| 09   | PUBLIC MSG        |\<from\>\<to\>\<msg\>   | Display users message to all users in his room     |
| 10   | AUTHENTICATED     |\<room\>            | Add user in room                                   |
| 11   | JOIN              |\<room\>            | Update prompt to new room                          |
| 12   | LISTOFALLUSERS    |\<listofusers\>     | Display the list of users                          |
| 13   | LISTOFROOMS       |\<listofrooms\>     | Display the list of rooms                          |
| 14   | WRONGPASS         |                  | Tell user the password was wrong, invite retry     |
| 15   | INUSE             |                  | Tell user the username is taken                    |
| 16   | TERMINATED        |                  | Terminate user                                     |
| 17   | PRIVATE MSG       |\<from\>\<to\>\<msg\>   | Display users message to recipient                 |
| 18   | NOSUCHNICK        |                  | Tell sender the recipient in non-existant                 |

#### Examples

| Reply      | Message                | Action                                              |
| ----------:|:-----------------------|:----------------------------------------------------|
| WELCOME    | "00:Guest1:Lobby\r\n"  | client is taken to the Lobby                        |
| PUBLIC MSG | "09:Atli:Ægir:Hæm\r\n" | Atli sends "Hæm" to Ægir                            |
| /say    | "06:Atli:Blessaður\r\n"| Atli is sent a private massage from client          |




