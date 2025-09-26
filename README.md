# opensrc-website

CYSCOM VIT's leaderboard hosted [here](https://opensrc.cyscomvit.com)

# Setup

### . Place a `.env` file

Format of `.env` file to be placed [here](./.env)

```env
START_ACT=3
END_ACT=6
CURRENT_ACT_YEAR=2024
FIREBASE_DB=https://project-id-full-name.firebaseio.com
FIREBASE_STORAGE=something.appspot.com
DEBUG=FALSE
```

1. Start act - The number of the act to start from when displaying the leaderboard.
2. END act - current act number in the database
3. Current act year - field just used to show the year beside the name of the acts in the dropdown
4. Firebase DB url `str`
5. Firebase storage url `str`
6. DEBUG True or False `bool`. Sets the command prefix to !cyscom-dev to differentiate from production deployement and for testing.

### 2. Run using docker

```sh
docker build -t cyscomvit/opensrc-website:latest .
docker run --detach --publish 5000:5000 --name opensrc-website-deploy cyscomvit/opensrc-website:latest
```

# Development

The project uses [Poetry](https://python-poetry.org/) to manage dependencies.

<details>
<summary>Why?</summary>
<br>
Poetry helps manage virtual environments easily.

It also pins versions of both dependencies and their dependencies recursively, unlike Pip. This means every package has an exact version and hash to check and download against.

With dependencies like `discord.py`, it became an issue since it's dependencies were not pinned and pip was installing the latest version, leading to many issues.
<br>

</details>

1.  Download `poetry` using Pip, or by following any of the other methods listed on their [website](https://python-poetry.org/docs/#installation)

```sh
pip install poetry
```

2. Create a virtual env and install all dependencies using poetry.

```sh
poetry install
```

    This will create and activate a virtual env. It will also install all dependencies from the poetry.lock file.

To add new dependencies:

```sh
poetry add package-name
```

Update it in the `requirements.txt` (**USING POETRY COMMANDS, DON'T EDIT IT MANUALLY**) file too. Even though we use poetry, having a usable requirements.txt file might be convient for others. It is also used to build the docker image, since having poetry installed makes the image larger (smaller image better). Since the requirements.txt file is kept up-to-date, the image can use `pip` to install it, without ever downloading or installing poetry.

```sh
poetry export -f requirements.txt -o requirements.txt
```

**MAKE SURE YOU ADD DEPENDENCIES USING POETRY FIRST, AND DO NOT USE PIP TO INSTALL ANY PACKAGE FOR THIS PROJECT**. This ensures the package's dependencies are also pinned in the `poetry.lock` file as well.
