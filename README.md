# Radicle HTTP API

This is a temporary fork of the original `radicle-httpd` API that allows us to keep `Create/Update/Delete` 
that was removed from the original API. 

We still need these to support: 
- machine-to-machine communication, such as integration with other 3rd party systems (e.g. CI engines that would typically want to _push_ updates to Radicle, once a job has completed),
- web applications that mutate project state, such as the [Radicle Planning Boards](https://explorer.radicle.gr/nodes/seed.radicle.gr/rad:z2BdUVZFvHdxRfdtGJQdSH2kyXNM6).


## License

This code is distributed under the terms of GPLv3. See [LICENSE][lic] for details.


[lic]: ./LICENSE
