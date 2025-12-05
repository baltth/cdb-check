# Check behavior of compiler diagnostic options

Compiler:
```
gcc-13 (Ubuntu 13.3.0-6ubuntu2~24.04) 13.3.0
Copyright (C) 2023 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.  There is NO
warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
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
- detected (W): `-Wall -Wunused -Wno-all`
- detected (E): `-Wall -Werror=unused`
- detected (E): `-Wall -Wno-unused -Werror=unused`
- detected (E): `-Wall -Werror=unused -Wno-all`

| -Wall | -Wno-unused | -Wunused | -Werror=unused | -Wno-all | detected |
|-------|-------------|----------|----------------|----------|----------|
|   X   |             |    X     |                |          |    W     |
|   X   |      X      |    X     |                |          |    W     |
|   X   |             |    X     |                |    X     |    W     |
|   X   |             |          |       X        |          |    E     |
|   X   |      X      |          |       X        |          |    E     |
|   X   |             |          |       X        |    X     |    E     |

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
- detected (E): `-Wunused -Werror -Wno-error=unused`
- detected (E): `-Wall -Werror -Wno-error=unused`
- not detected: `-Werror -Wno-error=unused`
- detected (E): `-Werror=unused -Wno-error=unused`

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
|    X     |       |    X    |                |             |         X         |    E     |
|          |   X   |    X    |                |             |         X         |    E     |
|          |       |    X    |                |             |         X         |          |
|          |       |         |       X        |             |         X         |    E     |

### Check if specific-then-generic sequence

Beginning with -Wno-unused:
- detected (W): `-Wno-unused -Wunused`
- not detected: `-Wno-unused -Wall`
- detected (E): `-Wno-unused -Wunused -Werror`
- not detected: `-Wno-unused -Wall -Werror`
- not detected: `-Wno-unused -Werror`
- detected (E): `-Wno-unused -Werror=unused`

With -Wno-error=unused added to the end:
- detected (W): `-Wno-unused -Wunused -Wno-error=unused`
- not detected: `-Wno-unused -Wall -Wno-error=unused`
- detected (E): `-Wno-unused -Wunused -Werror -Wno-error=unused`
- not detected: `-Wno-unused -Wall -Werror -Wno-error=unused`
- not detected: `-Wno-unused -Werror -Wno-error=unused`
- detected (E): `-Wno-unused -Werror=unused -Wno-error=unused`

| -Wno-unused | -Wunused | -Wall | -Werror | -Werror=unused | -Wno-error=unused | detected |
|-------------|----------|-------|---------|----------------|-------------------|----------|
|      X      |    X     |       |         |                |                   |    W     |
|      X      |          |   X   |         |                |                   |          |
|      X      |    X     |       |    X    |                |                   |    E     |
|      X      |          |   X   |    X    |                |                   |          |
|      X      |          |       |    X    |                |                   |          |
|      X      |          |       |         |       X        |                   |    E     |

| -Wno-unused | -Wunused | -Wall | -Werror | -Werror=unused | -Wno-error=unused | detected |
|-------------|----------|-------|---------|----------------|-------------------|----------|
|      X      |    X     |       |         |                |         X         |    W     |
|      X      |          |   X   |         |                |         X         |          |
|      X      |    X     |       |    X    |                |         X         |    E     |
|      X      |          |   X   |    X    |                |         X         |          |
|      X      |          |       |    X    |                |         X         |          |
|      X      |          |       |         |       X        |         X         |    E     |


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
- detected (E): `-Werror=unused -Wno-error=unused`
- detected (E): `-Werror=unused -Wno-error`
- not detected: `-Werror=unused -Wno-unused`
- not detected: `-Werror=unused -Wno-unused -Wno-error=unused`

After -Wno-unused:
- detected (E): `-Wno-unused -Werror=unused`
- detected (E): `-Wno-unused -Werror=unused -Wno-error=unused`
- detected (E): `-Wno-unused -Werror=unused -Wno-error`

| -Wno-unused | -Werror=unused | -Wno-unused | -Wno-error=unused | -Wno-error | detected |
|-------------|----------------|-------------|-------------------|------------|----------|
|             |       X        |             |                   |            |    E     |
|             |       X        |             |         X         |            |    E     |
|             |       X        |             |                   |     X      |    E     |
|             |       X        |      X      |                   |            |          |
|             |       X        |      X      |         X         |            |          |

| -Wno-unused | -Werror=unused | -Wno-unused | -Wno-error=unused | -Wno-error | detected |
|-------------|----------------|-------------|-------------------|------------|----------|
|      X      |       X        |             |                   |            |    E     |
|      X      |       X        |             |         X         |            |    E     |
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
- detected (E): `-Wunused -Wno-error=unused -Werror`

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
|    X     |         X         |             |          |    X    |                |    E     |

