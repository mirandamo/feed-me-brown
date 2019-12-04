## Feed Me README

# If Database breaks
<!-- Try clearing cache -->
$ heroku repo:purge_cache -a feed-me-brown

# If Internal Server Error
$ heroku run python3
$ import os
$ heroku config:set HEROKU=heroku
$ from app import db
$ db.create_all()

# To push master
$ heroku login
$ cd feed-me-brown
$ git add .
$ git commit -am "make it better"
$ git push heroku master
