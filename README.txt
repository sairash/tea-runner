# Tea Sprint
##### _Fork of [Tree Runnner](https://nodesource.com/products/nsolid)_

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Tea Sprint is a minimalist CI/CD for your Gitea server.


## Installation
```sh
docker-compose -f compose.yml up -d
```

## Features

- Ability to add username and password
- Ability to choose http or ssh connection
- Ability to run multiple commands
- Ability to add path

### Steps:

- Go to webhook in gitea and add
```
dest.example.io/rsync?dest=%2Fsrv%2Fwww&u
```
- If you need to add username or password add it to config file

## License
MIT
**Free Software, Hell Yeah!**
