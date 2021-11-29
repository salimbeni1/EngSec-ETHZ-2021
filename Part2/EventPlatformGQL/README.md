# Event Platform in GraphQL

This repository contains the event platform of the security engineering project implemented in GraphQL.

## Setup

To run and build the project, you need to install:
* [node](https://nodejs.org/en/download/)
* [docker](https://www.docker.com/get-started)
* And optionally, we recommend to use [Visual Studio Code](https://code.visualstudio.com/Download) to develop it

After you have installed the tools necessary, you need to setup a database.
For this, execute the following commands:
```sh
cd scripts
./db.ps1
./setup.ps1
```

Whenever you want to connect to the database, you can execute `scripts/mongo.ps1` to open a mongodb shell.

To compile and start the server, you initially need to run `npm install` once.
Then, you first need to start the database (`scripts/start.ps1`, might be necessary after rebooting, too) and then run one of the commands
* `npm run server` (project part II)
* `npm run server-rbac` (project part III)

Additionally, you can run tests by executing:
* `npm run test` (project part II)
* `npm run test-rbac` (project part III)

## The Repository

To provide you with an overview of the repository, we list all important folders and files here.
Respective folders contain another README detailing how they work.

File | Explanation
-----|------------
`index.ts` | Provides an API to create the GraphQL server
`start.ts` | Script to run the server
`datamodel/` | Contains all datamodel definitions
`permissions/` | Contains access control rules written in graphql-shield for project part II
`rb_permissions/` | Contains role-based access control rules written in  graphql-shield for project part III
`resolvers/` | Contains all GraphQL resolvers for the scheme `datamodel/gql-schema.ts`
`scripts/` | Contains database scripts
`tests/` | Contains test cases

## Tooling

As stated earlier, we recommend Visual Studio Code to modify this project.
Additionally, we recommend the extension [ESLint](https://marketplace.visualstudio.com/items?itemName=dbaeumer.vscode-eslint) for linting and optionally [GraphQL](https://marketplace.visualstudio.com/items?itemName=GraphQL.vscode-graphql) for some additional syntax highlighting.

This project comes with debugging already configured.
If you open the debugging pane (Ctrl+Shift+D), you can select one of two profiles for debugging:
1. Test this file: debug the tests in the file that is currently opened and focused.
2. Run: debug the server.
3. Run (RBAC): debug the server using role-based permissions.

## Additional Help

The following links can provide you with useful documentation:
* Documentation for GraphQL Shield: https://www.graphql-shield.com/docs
* How resolvers work: https://www.graphql-tools.com/docs/resolvers
* Introduction to GraphQL: https://graphql.org/learn/
* How to write queries in mongoose (the mongodb client we use): https://mongoosejs.com/docs/queries.html
* How to write queries for mongodb: https://docs.mongodb.com/manual/tutorial/query-documents/
* Reference of all query operators in mongodb: https://docs.mongodb.com/manual/reference/operator/
* GraphQL Shield is GraphQL middleware; this post details how middleware is executed: https://www.prisma.io/blog/graphql-middleware-zie3iphithxy
