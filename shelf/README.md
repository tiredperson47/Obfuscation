# Description

SHELF loading is just reflective loading but for Linux. I just copied the name from ULEXEC who called it SHELF loading.

# How to Use
1. Spawn a random, persistent process that you want to inject into. I like to use `nc -lvnp 4444` for simplicity
2. Get the process ID (PID). This can be done using `ss -tulpn` (if you're using netcat), or `ps aux`
3. Execute build_shelf.sh and follow the prompts.
4. Execute your payload and watch the output of your target process. Output should look something like this:

```sh
nc -lvnp 4444
listening on [any] 4444 ...
[+] Payload is running...
[+] Payload is running...
[+] Payload is quitting... Process will be restored and continue normally
```

5. Then you can try connecting to netcat to ensure the process reverted normally
```sh
echo "test" | nc 127.0.0.1 4444
```

# Notes
I intend to make a blog about how it all works eventually. Will be posted on my website at https://tiredperson47.github.io