# README

This is a dockerized version of the ActionGUI framework. It contains two images, a MySQL database and a lightweight linux machine with maven 3.5 and Java 8 installed. To start make sure you have docker installed and type:

`docker-compose up --build`

to build the images and run the containers the first time you use them. Note: If you are using an Apple M1 chip please see `actiongui-app/Dockerfile` and change the first import to specify the arm64 architecture.

Once the images have been built you can start and stop the containers using:

`docker-compose up`

and

`docker-compose stop`

## Compiling and executing Hello World

Once the containers are running (you can check this with `docker ps`  and you should see a mysql5 container and a container named `actiongui-app`) you can open a shell inside de maven container using:

`docker exec -it actiongui-app bash`

The directory `/usr/local/actiongui/` in the container is linked to the local `actiongui-app/projects/` in this folder.  This folder contains the Hello World example described in the course tutorial under the folder `phil`. To compile the code go to the shared folder in the container and execute maven:

    cd /usr/local/actiongui/phil
    mvn clean install

Next, to create the database, inside the container go to the shared directory and execute the `createDB.sh` script:

    cd /usr/local/actiongui/phil
    ./createDB.sh

or directly 

    cat ./vm/target/generated-sources/sql/db.sql | mysql -u'root' -p'actiongui' -h mysql -P 3306

Finally, to execute the compiled web application, go to the `phil/vm` directory:

    cd /usr/local/actiongui/phil/vm
    mvn jetty:run-war

The app should be reachable from your local machine under `localhost:8080/vm`. 

## Working on other projects

Since the folder  `/usr/local/actiongui/`  in the maven container and  the local `actiongui-app/projects/` are synchronized, you can edit files locally using your favorite code editor and see these changes reflected on the container.  You can try for instance to follow the more advanced examples in the course tutorial using the Hello World template as basis. 

If you would like to start a project from scratch, you can do so by generating one using maven archetypes on the shared folder:

`cd /usr/local/actiongui/`

    mvn archetype:generate  \ 
    -DgroupId=org.modelinglab  \ 
    -DartifactId=my-app  \
    -DarchetypeArtifactId=ag-archetype  \ 
    -DarchetypeVersion=2.5 \
    -DarchetypeGroupId=org.modelinglab.actiongui.maven.archetypes

This will create a new folder `my-app`. You can compile and run this similarly as the Hello World example. However make sure you adjust the DB settings under `./vm/src/test/resources/jetty/jetty-env.xml` in lines 13-15 to:

    <Set name="Url">jdbc:mysql://mysql:3306/my-app</Set> 
    <Set name="User">root</Set>
    <Set name="Password">actiongui</Set>

and to copy the `createDB.sh` script from the Hello World example in order to create the database for the new project.