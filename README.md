## Colorguard

Detect leaks of the flag page given an input.
Makes stdin entirely concrete with the only symbolic data being the flag page.
For most binaries this should allow us to execute almost entirely in Unicorn

```python
>>> cg = colorguard.Colorguard("../binaries/tests/i386/simple_leak", "deadbeef")
>>> cg.causes_leak()
True
```
