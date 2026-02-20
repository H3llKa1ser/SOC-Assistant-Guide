# Google Chrome

Location:

    C:\Users\USER\AppData\Local\Google\Chrome\User Data

Default Chrome user profile location

    C:\Users\USER\AppData\Local\Google\Chrome\User Data\Default

## Google Chrome Artifacts

| File / Directory Name | Artefact Contents                                                       | File Type                       |
|-----------------------|-------------------------------------------------------------------------|----------------------------------|
| `History`             | Contains the browsing history and download metadata                    | SQLite                           |
| `Login Data`          | Contains credentials saved through the browser                         | SQLite                           |
| `Extensions`          | Includes artefacts related to Chrome extensions                        | Folder (JavaScript and meta files) |
| `Cache`               | Includes cached files stored to optimise site loading                  | Folder                           |
| `Sessions`            | Handles sessions and tabs metadata                                     | Folder                           |
| `Bookmarks`           | Handles bookmark metadata                                              | JSON                             |
| `Web Data`            | Contains input data submitted by the user in web forms                 | SQLite                           |

### 1) Enumerate browsing data stored in each user's directory

    ls C:\Users\ | foreach {ls "C:\Users\$_\AppData\Local\Google\Chrome\User Data\Default" 2>$null | findstr Directory}

