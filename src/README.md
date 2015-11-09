

Protocol
========

## Our protocol:

We decided to use a text based protocol.
All messages between server and client start with the string "xx:" where xx is a number between 00 and 18.
Each number indicates a specific type of message shown below:

### Client Messages

| Code | Command           | Parameters       |Error reply      | Success reply | Server Action                          |
| ---- |:-----------------:| -----------------|----------------:|---------------|----------------------------------------|
| 01   | /user             |\<user\>\<password\>  | WRONGPASS, INUSE| AUTHENTICATED | Add user in Lobby and list of all users|
| 02   | /bye or /quit     |                  |                 | Disconnect    |                                        |
| 03   | /join             |\<room\>            |                 | JOIN          | Add user in room                       |
| 04   | /who              |<room>            |                 | LISTOFALLUSERS| Send the client a list of all users    |
| 05   | /list             |                  |                 | LISTOFROOMS   | Send the client a list of all rooms    |
| 06   | /say or none      |[<user>]<msg>     | NOSUCHNICK      | MSG           | Send private/public messages           |
| 07   | /game             |                  |                 |               |                                        |
| 08   | /roll             |                  |                 |               |                                        |

### Server Messages

| Code | Reply             | Parameters       | Client Action                                      |
| ---- |:-----------------:| -----------------|----------------------------------------------------|
| 00   | WELCOME           |<user><room>      | Set prompt to <user>@<room>>|and print Welcome msg |
| 09   | PUBLIC MSG        |<from><to><msg>   | Display users message to all users in his room     |
| 10   | AUTHENTICATED     |<room>            | Add user in room                                   |
| 11   | JOIN              |<room>            | Update prompt to new room                          |
| 12   | LISTOFALLUSERS    |<listofusers>     | Display the list of users                          |
| 13   | LISTOFROOMS       |<listofrooms>     | Display the list of rooms                          |
| 14   | WRONGPASS         |                  | Tell user the password was wrong, invite retry     |
| 15   | INUSE             |                  | Tell user the username is taken                    |
| 16   | TERMINATED        |                  | Terminate user                                     |
| 17   | PRIVATE MSG       |<from><to><msg>   | Display users message to recipient                 |
| 18   | NOSUCHNICK        |                  | Tell user the user in non-existant                 |





