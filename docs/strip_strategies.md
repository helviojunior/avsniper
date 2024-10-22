# Strip strategy

In a general way `strip` (for this software purposes) is the act to change part os the binary file.

This software is prepared to work in 2 different ways `direct` and `reversed` and each one generates several EXE files using 3 techniques as listed bellow:

1.  Unique: Just one original string is kept at the file, all other strings are replaced by random strings
2.  Incremental: The strings are being put at the file one-by-one 
3.  Sliced: Just a range of 30 strings is kept at the file, all other strings are replaced by random strings. 

In general way `direct` strategy first remove all enumerated strings and will putting back one by one previous enumerated strings. In other hands, as the name suggests, the `reverse` strategy keep all the original EXE file and will removing one by one previous enumerated strings.

So, let's see how each one works

## Direct 

`Direct` is the technique that follows this steps:

1.  Replace all identified string with a random data
2.  Put back one by one original string

Let's see with the images bellow how each combination (`direct - unique`, `direct incremental` and `direct slices`) works

### Direct - Unique

#### Original file
![Fully striped](https://github.com/helviojunior/avsniper/blob/main/docs/images/direct_unique/001.png)

#### Fully striped
![Fully striped](https://github.com/helviojunior/avsniper/blob/main/docs/images/direct_unique/002.png)

#### Putting back one by one string

![String 01](https://github.com/helviojunior/avsniper/blob/main/docs/images/direct_unique/003.png)
![String 02](https://github.com/helviojunior/avsniper/blob/main/docs/images/direct_unique/004.png)
![String 03](https://github.com/helviojunior/avsniper/blob/main/docs/images/direct_unique/005.png)
![String 04](https://github.com/helviojunior/avsniper/blob/main/docs/images/direct_unique/006.png)
![String 05](https://github.com/helviojunior/avsniper/blob/main/docs/images/direct_unique/007.png)
![String 06](https://github.com/helviojunior/avsniper/blob/main/docs/images/direct_unique/008.png)
![String 07](https://github.com/helviojunior/avsniper/blob/main/docs/images/direct_unique/009.png)
![String 08](https://github.com/helviojunior/avsniper/blob/main/docs/images/direct_unique/010.png)
![String 09](https://github.com/helviojunior/avsniper/blob/main/docs/images/direct_unique/011.png)
![String 10](https://github.com/helviojunior/avsniper/blob/main/docs/images/direct_unique/012.png)
![String 11](https://github.com/helviojunior/avsniper/blob/main/docs/images/direct_unique/013.png)

### Direct - Incremental

#### Fully striped
![Fully striped](https://github.com/helviojunior/avsniper/blob/main/docs/images/direct_incremental/002.png)

#### Putting back one by one string

![String 01](https://github.com/helviojunior/avsniper/blob/main/docs/images/direct_incremental/003.png)
![String 02](https://github.com/helviojunior/avsniper/blob/main/docs/images/direct_incremental/004.png)
![String 03](https://github.com/helviojunior/avsniper/blob/main/docs/images/direct_incremental/005.png)
![String 04](https://github.com/helviojunior/avsniper/blob/main/docs/images/direct_incremental/006.png)
![String 05](https://github.com/helviojunior/avsniper/blob/main/docs/images/direct_incremental/007.png)
![String 06](https://github.com/helviojunior/avsniper/blob/main/docs/images/direct_incremental/008.png)
![String 07](https://github.com/helviojunior/avsniper/blob/main/docs/images/direct_incremental/009.png)
![String 08](https://github.com/helviojunior/avsniper/blob/main/docs/images/direct_incremental/010.png)
![String 09](https://github.com/helviojunior/avsniper/blob/main/docs/images/direct_incremental/011.png)
![String 10](https://github.com/helviojunior/avsniper/blob/main/docs/images/direct_incremental/012.png)
![String 11](https://github.com/helviojunior/avsniper/blob/main/docs/images/direct_incremental/013.png)


### Direct - Sliced

#### Fully striped
![Fully striped](https://github.com/helviojunior/avsniper/blob/main/docs/images/direct_sliced/001.png)

#### Putting back one by one string

![String 01](https://github.com/helviojunior/avsniper/blob/main/docs/images/direct_sliced/002.png)
![String 02](https://github.com/helviojunior/avsniper/blob/main/docs/images/direct_sliced/003.png)
![String 03](https://github.com/helviojunior/avsniper/blob/main/docs/images/direct_sliced/004.png)
![String 04](https://github.com/helviojunior/avsniper/blob/main/docs/images/direct_sliced/005.png)
![String 05](https://github.com/helviojunior/avsniper/blob/main/docs/images/direct_sliced/006.png)
![String 06](https://github.com/helviojunior/avsniper/blob/main/docs/images/direct_sliced/007.png)
![String 07](https://github.com/helviojunior/avsniper/blob/main/docs/images/direct_sliced/008.png)
![String 08](https://github.com/helviojunior/avsniper/blob/main/docs/images/direct_sliced/009.png)
![String 09](https://github.com/helviojunior/avsniper/blob/main/docs/images/direct_sliced/010.png)
![String 10](https://github.com/helviojunior/avsniper/blob/main/docs/images/direct_sliced/011.png)
![String 11](https://github.com/helviojunior/avsniper/blob/main/docs/images/direct_sliced/012.png)
![String 11](https://github.com/helviojunior/avsniper/blob/main/docs/images/direct_sliced/013.png)
![String 11](https://github.com/helviojunior/avsniper/blob/main/docs/images/direct_sliced/014.png)

## Reversed

`Reversed` is the technique that follows this steps:

1.  Keep original file with all original data
2.  Replace one by one identified string with random data

Let's see with the images bellow how each combination (`reversed - unique`, `reversed incremental` and `reversed slices`) works

### Reversed - Unique

#### Fully original
![Fully striped](https://github.com/helviojunior/avsniper/blob/main/docs/images/reversed_unique/001.png)

#### Putting back one by one string

![String 01](https://github.com/helviojunior/avsniper/blob/main/docs/images/reversed_unique/002.png)
![String 02](https://github.com/helviojunior/avsniper/blob/main/docs/images/reversed_unique/003.png)
![String 03](https://github.com/helviojunior/avsniper/blob/main/docs/images/reversed_unique/004.png)
![String 04](https://github.com/helviojunior/avsniper/blob/main/docs/images/reversed_unique/005.png)
![String 05](https://github.com/helviojunior/avsniper/blob/main/docs/images/reversed_unique/006.png)
![String 06](https://github.com/helviojunior/avsniper/blob/main/docs/images/reversed_unique/007.png)
![String 07](https://github.com/helviojunior/avsniper/blob/main/docs/images/reversed_unique/008.png)
![String 08](https://github.com/helviojunior/avsniper/blob/main/docs/images/reversed_unique/009.png)
![String 09](https://github.com/helviojunior/avsniper/blob/main/docs/images/reversed_unique/010.png)
![String 10](https://github.com/helviojunior/avsniper/blob/main/docs/images/reversed_unique/011.png)
![String 11](https://github.com/helviojunior/avsniper/blob/main/docs/images/reversed_unique/012.png)

### Reversed - Incremental

#### Fully original
![Fully striped](https://github.com/helviojunior/avsniper/blob/main/docs/images/reversed_incremental/001.png)

#### Putting back one by one string

![String 01](https://github.com/helviojunior/avsniper/blob/main/docs/images/reversed_incremental/002.png)
![String 02](https://github.com/helviojunior/avsniper/blob/main/docs/images/reversed_incremental/003.png)
![String 03](https://github.com/helviojunior/avsniper/blob/main/docs/images/reversed_incremental/004.png)
![String 04](https://github.com/helviojunior/avsniper/blob/main/docs/images/reversed_incremental/005.png)
![String 05](https://github.com/helviojunior/avsniper/blob/main/docs/images/reversed_incremental/006.png)
![String 06](https://github.com/helviojunior/avsniper/blob/main/docs/images/reversed_incremental/007.png)
![String 07](https://github.com/helviojunior/avsniper/blob/main/docs/images/reversed_incremental/008.png)
![String 08](https://github.com/helviojunior/avsniper/blob/main/docs/images/reversed_incremental/009.png)
![String 09](https://github.com/helviojunior/avsniper/blob/main/docs/images/reversed_incremental/010.png)
![String 10](https://github.com/helviojunior/avsniper/blob/main/docs/images/reversed_incremental/011.png)
![String 11](https://github.com/helviojunior/avsniper/blob/main/docs/images/reversed_incremental/012.png)


### Reversed - Sliced

#### Fully original
![Fully striped](https://github.com/helviojunior/avsniper/blob/main/docs/images/reversed_sliced/001.png)

#### Putting back one by one string

![String 01](https://github.com/helviojunior/avsniper/blob/main/docs/images/reversed_sliced/002.png)
![String 02](https://github.com/helviojunior/avsniper/blob/main/docs/images/reversed_sliced/003.png)
![String 03](https://github.com/helviojunior/avsniper/blob/main/docs/images/reversed_sliced/004.png)
![String 04](https://github.com/helviojunior/avsniper/blob/main/docs/images/reversed_sliced/005.png)
![String 05](https://github.com/helviojunior/avsniper/blob/main/docs/images/reversed_sliced/006.png)
![String 06](https://github.com/helviojunior/avsniper/blob/main/docs/images/reversed_sliced/007.png)
![String 07](https://github.com/helviojunior/avsniper/blob/main/docs/images/reversed_sliced/008.png)
![String 08](https://github.com/helviojunior/avsniper/blob/main/docs/images/reversed_sliced/009.png)
![String 09](https://github.com/helviojunior/avsniper/blob/main/docs/images/reversed_sliced/010.png)
![String 10](https://github.com/helviojunior/avsniper/blob/main/docs/images/reversed_sliced/011.png)
![String 11](https://github.com/helviojunior/avsniper/blob/main/docs/images/reversed_sliced/012.png)
![String 11](https://github.com/helviojunior/avsniper/blob/main/docs/images/reversed_sliced/013.png)
![String 11](https://github.com/helviojunior/avsniper/blob/main/docs/images/reversed_sliced/014.png)
