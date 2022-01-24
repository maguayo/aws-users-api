import os
from pynamodb.attributes import (
    UnicodeAttribute,
    NumberAttribute,
    MapAttribute,
    ListAttribute,
)
from datetime import datetime
import json

from pynamodb.models import Model


class BaseModel(Model):
    def to_json(self, indent=2):
        return json.dumps(self.to_dict(), indent=indent)

    def to_dict(self):
        ret_dict = {}
        for name, attr in self.attribute_values.items():
            ret_dict[name] = self._attr2obj(attr)

        return ret_dict

    def _attr2obj(self, attr):
        # compare with list class. It is not ListAttribute.
        if isinstance(attr, list):
            _list = []
            for l in attr:
                _list.append(self._attr2obj(l))
            return _list
        elif isinstance(attr, MapAttribute):
            _dict = {}
            for k, v in attr.attribute_values.items():
                _dict[k] = self._attr2obj(v)
            return _dict
        elif isinstance(attr, datetime):
            return attr.isoformat()
        else:
            return attr


class Users(BaseModel):
    class Meta:
        table_name = os.environ.get("USERS_TABLE", "example-users")
        region = os.environ.get("REGION", "eu-west-3")

    id = UnicodeAttribute()
    email = UnicodeAttribute(hash_key=True)
    account_type = NumberAttribute()
    first_name = UnicodeAttribute()
    last_name = UnicodeAttribute()
    password = UnicodeAttribute()
    phone = UnicodeAttribute()
    cif = UnicodeAttribute()
    city = UnicodeAttribute()
    address = UnicodeAttribute()
    created_at = NumberAttribute()
    modified = NumberAttribute()
    utms = MapAttribute()
