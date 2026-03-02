from typing import Annotated

from sqlalchemy import String
from sqlalchemy.orm import DeclarativeBase

# Type aliases for column lengths
str_100 = Annotated[str, 100]
str_150 = Annotated[str, 150]
str_4000 = Annotated[str, 4000]


class Base(DeclarativeBase):
    """Base class for all models."""

    type_annotation_map = {
        str_100: String(100),
        str_150: String(150),
        str_4000: String(4000),
    }
