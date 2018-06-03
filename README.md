# rehash
This is largely inspired by grugq's _hash_ utility:
- https://grugq.github.io/presentations/hacking_sucks.pdf

I wanted to make it as close to _netcat_ behavior as possible to lower the
learning curve of a new tool.

This code is currently buggy and incomplete.

## example usage
```
./rehash host port
...
Control-C
rehash> upgrayedd
www-data@web1:$
...
Control-C
rehash> help
<shows which commands are available>
```

