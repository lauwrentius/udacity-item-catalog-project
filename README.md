Udacity Item Catalog Application
=============


This is a project assigned by Udacity in part of the [Udacity Full Stack Nanodegree](https://www.udacity.com/course/full-stack-web-developer-nanodegree--nd004) program.

## About
This application displays list of items within a variety of categories. It allows the user to sign in using various authentication system. Signed in users will have the ability to post, edit and delete items listed.

The application runs on a VM using *Vagrant*. It's build with *Python* and uses *Flask* framework and *sqlite* for storing data. It uses *OAuth2* framework as a form of user authentication. Users are able to select between *Google*, *Facebook*, or *Github* as third-party authentication platforms.

## Installation

1. Install *Vagrant* and *VirtualBox*
2. Clone this repo
3. Launch and Connect Vagrant virtal machine (from the repo directory) `vagrant up`, `vagrant ssh`
5. Navigate to the project folder `\vagrant\catalog`
6. Run Python `python webserver.py`
7. Web apps can be accessed from [http://localhost:5000](http://localhost:5000)


## JSON Endpoints
  * `/json` - Lists all of the categories and items
  * `/catalog/<catalog-id>/json` - List all of the items from a category
  * `/item/<item-id>/json` - Displays a specific item
