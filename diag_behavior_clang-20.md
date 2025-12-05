# Check behavior of compiler diagnostic options

Compiler:
```
Ubuntu clang version 20.1.2 (0ubuntu1~24.04.2)
Target: x86_64-pc-linux-gnu
Thread model: posix
InstalledDir: /usr/lib/llvm-20/bin
```

## Checks for detecting unused variable

Source:
```c
unsigned foo(void) {
    int unused = 32;
    return 14U;
}
```

### Check basic switches

- detected (W): `-Wunused`
- detected (W): `-Wall`
- detected (E): `-Wunused -Werror`
- detected (E): `-Wall -Werror`
- not detected: `-Werror`
- detected (E): `-Werror=unused`

| -Wunused | -Wall | -Werror | -Werror=unused | detected |
|----------|-------|---------|----------------|----------|
|    X     |       |         |                |    W     |
|          |   X   |         |                |    W     |
|    X     |       |    X    |                |    E     |
|          |   X   |    X    |                |    E     |
|          |       |    X    |                |          |
|          |       |         |       X        |    E     |

### Check generic combinations

- detected (E): `-Wall -Werror`
- not detected: `-Wall -Werror -Wno-all`
- detected (W): `-Wall -Werror -Wno-error`
- detected (E): `-Werror -Wall`
- detected (W): `-Werror -Wall -Wno-error`

| -Wall | -Werror | -Wno-all | -Wno-error | -Wall | -Wno-error | detected |
|-------|---------|----------|------------|-------|------------|----------|
|   X   |    X    |          |            |       |            |    E     |
|   X   |    X    |    X     |            |       |            |          |
|   X   |    X    |          |     X      |       |            |    W     |
|       |    X    |          |            |   X   |            |    E     |
|       |    X    |          |            |   X   |     X      |    W     |

### Check specific enablers

- detected (W): `-Wall -Wunused`
- detected (W): `-Wall -Wno-unused -Wunused`
- not detected: `-Wall -Wunused -Wno-all`
- detected (E): `-Wall -Werror=unused`
- detected (E): `-Wall -Wno-unused -Werror=unused`
- not detected: `-Wall -Werror=unused -Wno-all`

| -Wall | -Wno-unused | -Wunused | -Werror=unused | -Wno-all | detected |
|-------|-------------|----------|----------------|----------|----------|
|   X   |             |    X     |                |          |    W     |
|   X   |      X      |    X     |                |          |    W     |
|   X   |             |    X     |                |    X     |          |
|   X   |             |          |       X        |          |    E     |
|   X   |      X      |          |       X        |          |    E     |
|   X   |             |          |       X        |    X     |          |

### Check specific disablers

With -Wno-unused:
- not detected: `-Wunused -Wno-unused`
- not detected: `-Wall -Wno-unused`
- not detected: `-Wunused -Werror -Wno-unused`
- not detected: `-Wall -Werror -Wno-unused`
- not detected: `-Werror -Wno-unused`
- not detected: `-Werror=unused -Wno-unused`

With -Wno-error=unused:
- detected (W): `-Wunused -Wno-error=unused`
- detected (W): `-Wall -Wno-error=unused`
- detected (W): `-Wunused -Werror -Wno-error=unused`
- detected (W): `-Wall -Werror -Wno-error=unused`
- not detected: `-Werror -Wno-error=unused`
- detected (W): `-Werror=unused -Wno-error=unused`

| -Wunused | -Wall | -Werror | -Werror=unused | -Wno-unused | -Wno-error=unused | detected |
|----------|-------|---------|----------------|-------------|-------------------|----------|
|    X     |       |         |                |      X      |                   |          |
|          |   X   |         |                |      X      |                   |          |
|    X     |       |    X    |                |      X      |                   |          |
|          |   X   |    X    |                |      X      |                   |          |
|          |       |    X    |                |      X      |                   |          |
|          |       |         |       X        |      X      |                   |          |

| -Wunused | -Wall | -Werror | -Werror=unused | -Wno-unused | -Wno-error=unused | detected |
|----------|-------|---------|----------------|-------------|-------------------|----------|
|    X     |       |         |                |             |         X         |    W     |
|          |   X   |         |                |             |         X         |    W     |
|    X     |       |    X    |                |             |         X         |    W     |
|          |   X   |    X    |                |             |         X         |    W     |
|          |       |    X    |                |             |         X         |          |
|          |       |         |       X        |             |         X         |    W     |

### Check if specific-then-generic sequence

Beginning with -Wno-unused:
- detected (W): `-Wno-unused -Wunused`
- detected (W): `-Wno-unused -Wall`
- detected (E): `-Wno-unused -Wunused -Werror`
- detected (E): `-Wno-unused -Wall -Werror`
- not detected: `-Wno-unused -Werror`
- detected (E): `-Wno-unused -Werror=unused`

With -Wno-error=unused added to the end:
- detected (W): `-Wno-unused -Wunused -Wno-error=unused`
- detected (W): `-Wno-unused -Wall -Wno-error=unused`
- detected (W): `-Wno-unused -Wunused -Werror -Wno-error=unused`
- detected (W): `-Wno-unused -Wall -Werror -Wno-error=unused`
- not detected: `-Wno-unused -Werror -Wno-error=unused`
- detected (W): `-Wno-unused -Werror=unused -Wno-error=unused`

| -Wno-unused | -Wunused | -Wall | -Werror | -Werror=unused | -Wno-error=unused | detected |
|-------------|----------|-------|---------|----------------|-------------------|----------|
|      X      |    X     |       |         |                |                   |    W     |
|      X      |          |   X   |         |                |                   |    W     |
|      X      |    X     |       |    X    |                |                   |    E     |
|      X      |          |   X   |    X    |                |                   |    E     |
|      X      |          |       |    X    |                |                   |          |
|      X      |          |       |         |       X        |                   |    E     |

| -Wno-unused | -Wunused | -Wall | -Werror | -Werror=unused | -Wno-error=unused | detected |
|-------------|----------|-------|---------|----------------|-------------------|----------|
|      X      |    X     |       |         |                |         X         |    W     |
|      X      |          |   X   |         |                |         X         |    W     |
|      X      |    X     |       |    X    |                |         X         |    W     |
|      X      |          |   X   |    X    |                |         X         |    W     |
|      X      |          |       |    X    |                |         X         |          |
|      X      |          |       |         |       X        |         X         |    W     |


Beginning with -Wno-error=unused:
- detected (W): `-Wno-error=unused -Wunused`
- detected (W): `-Wno-error=unused -Wall`
- not detected: `-Wno-error=unused -Werror`
- detected (E): `-Wno-error=unused -Werror=unused`

With -Wno-unused added to the end:
- not detected: `-Wno-error=unused -Wunused -Wno-unused`
- not detected: `-Wno-error=unused -Wall -Wno-unused`
- not detected: `-Wno-error=unused -Werror -Wno-unused`
- not detected: `-Wno-error=unused -Werror=unused -Wno-unused`

| -Wno-error=unused | -Wunused | -Wall | -Werror | -Werror=unused | -Wno-unused | detected |
|-------------------|----------|-------|---------|----------------|-------------|----------|
|         X         |    X     |       |         |                |             |    W     |
|         X         |          |   X   |         |                |             |    W     |
|         X         |          |       |    X    |                |             |          |
|         X         |          |       |         |       X        |             |    E     |

| -Wno-error=unused | -Wunused | -Wall | -Werror | -Werror=unused | -Wno-unused | detected |
|-------------------|----------|-------|---------|----------------|-------------|----------|
|         X         |    X     |       |         |                |      X      |          |
|         X         |          |   X   |         |                |      X      |          |
|         X         |          |       |    X    |                |      X      |          |
|         X         |          |       |         |       X        |      X      |          |

### Check -Werror= behavior

- detected (E): `-Werror=unused`
- detected (W): `-Werror=unused -Wno-error=unused`
- detected (E): `-Werror=unused -Wno-error`
- not detected: `-Werror=unused -Wno-unused`
- not detected: `-Werror=unused -Wno-unused -Wno-error=unused`

After -Wno-unused:
- detected (E): `-Wno-unused -Werror=unused`
- detected (W): `-Wno-unused -Werror=unused -Wno-error=unused`
- detected (E): `-Wno-unused -Werror=unused -Wno-error`

| -Wno-unused | -Werror=unused | -Wno-unused | -Wno-error=unused | -Wno-error | detected |
|-------------|----------------|-------------|-------------------|------------|----------|
|             |       X        |             |                   |            |    E     |
|             |       X        |             |         X         |            |    W     |
|             |       X        |             |                   |     X      |    E     |
|             |       X        |      X      |                   |            |          |
|             |       X        |      X      |         X         |            |          |

| -Wno-unused | -Werror=unused | -Wno-unused | -Wno-error=unused | -Wno-error | detected |
|-------------|----------------|-------------|-------------------|------------|----------|
|      X      |       X        |             |                   |            |    E     |
|      X      |       X        |             |         X         |            |    W     |
|      X      |       X        |             |                   |     X      |    E     |

### Check -Wno-error= behavior

- not detected: `-Wno-error=unused`
- not detected: `-Wno-error=unused -Wno-unused`
- detected (W): `-Wno-error=unused -Wunused`
- not detected: `-Wno-error=unused -Werror`
- detected (E): `-Wno-error=unused -Werror=unused`
- detected (E): `-Wno-error=unused -Wunused -Werror=unused`

After -Wunused:
- detected (W): `-Wunused -Wno-error=unused`
- detected (W): `-Wunused -Wno-error=unused -Werror`

| -Wunused | -Wno-error=unused | -Wno-unused | -Wunused | -Werror | -Werror=unused | detected |
|----------|-------------------|-------------|----------|---------|----------------|----------|
|          |         X         |             |          |         |                |          |
|          |         X         |      X      |          |         |                |          |
|          |         X         |             |    X     |         |                |    W     |
|          |         X         |             |          |    X    |                |          |
|          |         X         |             |          |         |       X        |    E     |
|          |         X         |             |    X     |         |       X        |    E     |

| -Wunused | -Wno-error=unused | -Wno-unused | -Wunused | -Werror | -Werror=unused | detected |
|----------|-------------------|-------------|----------|---------|----------------|----------|
|    X     |         X         |             |          |         |                |    W     |
|    X     |         X         |             |          |    X    |                |    W     |

