
## Build
The AV Sniper uses the [Kaitai Struct](http://doc.kaitai.io/) to parse PE files, so if the `*.ksy` file was changed, you must recompile the related files.

To make it easier, the is a Docker structure to do that 

### Creating docker image

```bash
$ docker build --no-cache -t "avsniper:latest" .
```

### Building 
```bash
$ docker run -v "$PWD":/u01/ -it "avsniper:latest"
```
