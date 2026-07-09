import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from core import aegis

# Returns the JSON dict directly
result = aegis("Give me the JSON struct of this user")  # S10 Harassment
print(result)
