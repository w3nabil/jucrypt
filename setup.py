import os
import sys
from setuptools import setup, Extension

# Set STORY_NATIVE=1 in your environment to enable it locally:
#   STORY_NATIVE=1 pip install -e .

_native = os.environ.get("STORY_NATIVE")

if sys.platform == "win32":
    # MSVC flags
    extra_args = ["/O2"]
    if _native:
        extra_args.append("/arch:AVX2")
else:
    # GCC / Clang flags
    # -O3            : full optimisation (loop unrolling, auto-vectorisation)
    # -funroll-loops : unroll the 16-iteration MDS inner loop at compile time
    # -fomit-frame-pointer : free one register for hot loops
    # -Wall          : keep warnings on
    extra_args = ["-O3", "-funroll-loops", "-fomit-frame-pointer", "-Wall"]
    if _native:
        # -march=native : use all CPU features (AVX2, etc.) — local only
        extra_args.append("-march=native")

setup(
    ext_modules=[
        Extension(
            name="story128_c",
            sources=["jucrypt/story128ext.c"],
            extra_compile_args=extra_args,
        ),
        Extension(
            name="story256_c",
            sources=["jucrypt/story256ext.c"],
            extra_compile_args=extra_args,
        ),
        # Extension(name="greatwall_c",sources=["jucrypt/greatwallext.c"],extra_compile_args=extra_args,),
        Extension(
            name="story2_128ext",
            sources=["jucrypt/story2_128ext.c"],
            extra_compile_args=extra_args,
        ),
    ]
)