"""The retail catalogue, normalised into something a payment rail can price.

The benign half of the generated corpus rests on this: real product names, real
categories and **real prices**, so the false-block rate becomes a measurement of
a stated cap policy against a real price distribution rather than against prices
somebody invented to make a point.

Four normalisations, and each one is a place a mistake would be invisible
downstream:

``price -> integer paise``
    The rail settles in integer paise and the amount lattice is defined over
    integers. A float rupee price that reached a signed cart would make check
    3's sum conjunct a floating-point comparison.
``currency``
    The dataset is Indian and its prices are rupees. Recorded rather than
    assumed, and a row whose price does not parse as a rupee figure is dropped.
``category -> the scope vocabulary``
    ``allowed_categories`` in an intent is a closed vocabulary the checks
    compare against. A category string taken straight from the dataset would
    make every intent's scope a different vocabulary and check 3's category
    conjunct unfalsifiable.
``pid -> SKU``
    SKUs have a shape in this project (``SK-...``) and the stand-in's
    substitution rule matches it. A SKU the pattern does not recognise would
    make class A3 unreachable on that product and the case would score as a
    defence.

**Rows are dropped, never coerced, and every drop is counted.** A coerced price
is a silent change to the amount lattice; a coerced category is a silent change
to what an intent authorises. :class:`CatalogueBuild` carries the counts and
:mod:`harness.generate.manifest` publishes them, because a generator that
quietly discarded four fifths of its input would produce a corpus nobody could
argue with.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from harness.datasets import read_rows

__all__ = [
    "SOURCE_ROLE",
    "SOURCE_FILE",
    "CURRENCY",
    "SCOPE_CATEGORIES",
    "CATEGORY_MAP",
    "SHIPPING_SKU",
    "SHIPPING_PAISE",
    "Product",
    "CatalogueBuild",
    "build_catalogue",
]

SOURCE_ROLE = "retail_catalogue"
SOURCE_FILE = "flipkart_com-ecommerce_sample.csv"

#: The dataset is an Indian storefront crawl and its prices are rupees. Stated
#: as a constant and checked, rather than assumed at the point of division.
CURRENCY = "INR"

#: The vocabulary an intent's ``allowed_categories`` may contain. Closed, for
#: the same reason the injection points and the attack classes are closed: a
#: scope built from free-text categories cannot be reasoned about, and check 3
#: comparing against a vocabulary nobody declared is a check that always passes.
#:
#: ``shipping`` is ours — it is the shipping line, not a product category — and
#: it is in every generated intent's scope for the same reason it is in the
#: hand-written ones.
SCOPE_CATEGORIES: tuple[str, ...] = (
    "automotive",
    "clothing",
    "electronics",
    "home",
    "jewellery",
    "personal_care",
    "shipping",
    "sports",
    "stationery",
)

#: Flipkart's top-level category to ours. Closed and total over the categories
#: worth keeping: a row whose top-level category is not a key here is **dropped
#: and counted**, never filed under a default. A default bucket would put
#: unrelated goods inside one authorised category, and an intent that
#: authorised "everything we could not place" authorises everything.
CATEGORY_MAP: dict[str, str] = {
    "Automotive": "automotive",
    "Tools & Hardware": "automotive",
    "Bags, Wallets & Belts": "clothing",
    "Clothing": "clothing",
    "Eyewear": "clothing",
    "Footwear": "clothing",
    "Sunglasses": "clothing",
    "Watches": "clothing",
    "Cameras & Accessories": "electronics",
    "Computers": "electronics",
    "Gaming": "electronics",
    "Health & Personal Care Appliances": "electronics",
    "Home Entertainment": "electronics",
    "Mobiles & Accessories": "electronics",
    "Furniture": "home",
    "Home & Kitchen": "home",
    "Home Decor & Festive Needs": "home",
    "Home Furnishing": "home",
    "Home Improvement": "home",
    "Household Supplies": "home",
    "Kitchen & Dining": "home",
    "Jewellery": "jewellery",
    "Baby Care": "personal_care",
    "Beauty and Personal Care": "personal_care",
    "Food & Nutrition": "personal_care",
    "Pet Supplies": "personal_care",
    "Sports & Fitness": "sports",
    "Pens & Stationery": "stationery",
    "Toys & School Supplies": "stationery",
}

#: The shipping line the generated storefront adds, matching the hand-written
#: corpus's. Ours, not the dataset's — the crawl has no delivery charge column —
#: and flat, so it is never the reason a task lands above its cap.
SHIPPING_SKU = "SK-SHIP-STD"
SHIPPING_PAISE = 4000

#: The shape a SKU has in this project. ``agent/llm.py``'s ``SKU_PATTERN`` is
#: the reader; this is the writer, and a SKU minted outside the pattern would
#: make class A3 and class A5 unreachable on that product.
SKU_SHAPE = re.compile(r"^SK-[A-Z0-9]{2,12}(?:-[A-Z0-9]{1,6})?$")

#: A dataset ``pid``, as the crawl writes them: sixteen uppercase alphanumerics.
PID_SHAPE = re.compile(r"^[A-Z0-9]{12,20}$")

#: Prices outside this band are dropped. The bottom excludes rows priced at a
#: rupee or two, which are data errors rather than products; the top excludes
#: the handful of five-lakh items whose cap would swamp every other task's.
#: Both bounds are declared here and applied blind, and the number of rows each
#: one removes is counted.
MIN_PAISE = 5_000
MAX_PAISE = 5_000_000

#: How much of the dataset's description survives into the product page. Long
#: enough to be prose an attack has to sit inside, short enough that a corpus
#: of four hundred products is a file rather than a database.
DESCRIPTION_CHARS = 320


@dataclass(frozen=True)
class Product:
    """One admitted catalogue row, in the units the rail uses."""

    sku: str
    name: str
    unit_amount: int
    category: str
    description: str
    brand: str
    source_pid: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "sku": self.sku,
            "name": self.name,
            "unit_amount": self.unit_amount,
            "category": self.category,
            "description": self.description,
            "brand": self.brand,
            "source_pid": self.source_pid,
        }


@dataclass
class CatalogueBuild:
    """The admitted products, and an itemised account of everything refused."""

    products: list[Product] = field(default_factory=list)
    dropped: dict[str, int] = field(default_factory=dict)
    rows_read: int = 0

    def drop(self, reason: str) -> None:
        self.dropped[reason] = self.dropped.get(reason, 0) + 1

    @property
    def dropped_total(self) -> int:
        return sum(self.dropped.values())

    def report(self) -> dict[str, Any]:
        return {
            "rows_read": self.rows_read,
            "admitted": len(self.products),
            "dropped": dict(sorted(self.dropped.items())),
            "dropped_total": self.dropped_total,
            "drop_rate": (
                round(self.dropped_total / self.rows_read, 6) if self.rows_read else 0.0
            ),
            "categories": {
                category: sum(1 for p in self.products if p.category == category)
                for category in sorted({p.category for p in self.products})
            },
        }


def _top_category(raw: str) -> str | None:
    """The first segment of the first path in the crawl's category tree.

    The column is a JSON list of ``">>"``-separated paths, and some rows carry
    the product's own name there instead of a category. Those parse and then
    fail :data:`CATEGORY_MAP`, which is the drop we want: a row whose category
    is its own name has no category.
    """
    try:
        tree = json.loads(raw)
    except (ValueError, TypeError):
        return None
    if not isinstance(tree, list) or not tree:
        return None
    first = str(tree[0]).split(">>")[0].strip()
    return first or None


def _paise(raw: str) -> int | None:
    try:
        rupees = float(str(raw).replace(",", "").strip())
    except (TypeError, ValueError):
        return None
    if rupees <= 0:
        return None
    return int(round(rupees * 100))


def _sku_for(pid: str) -> str | None:
    """A project-shaped SKU derived from the crawl's own product id.

    Derived rather than counted from one, so the same dataset row produces the
    same SKU on every run and a case that names ``SK-SRTEH2FF-9KED`` can be
    traced back to the row it came from.
    """
    if not PID_SHAPE.match(pid or ""):
        return None
    sku = f"SK-{pid[:8]}-{pid[8:12]}"
    return sku if SKU_SHAPE.match(sku) else None


def _clean(text: str) -> str:
    """One line of prose, with the crawl's escaping and whitespace flattened."""
    collapsed = re.sub(r"\s+", " ", (text or "").replace("\\n", " ")).strip()
    if len(collapsed) <= DESCRIPTION_CHARS:
        return collapsed
    cut = collapsed[:DESCRIPTION_CHARS].rsplit(" ", 1)[0]
    return cut + "…"


def build_catalogue(*, limit: int | None = None) -> CatalogueBuild:
    """Read the pinned crawl and admit the rows a storefront can serve.

    The digest check happens inside :func:`~harness.datasets.read_rows`, so
    there is no path through this function that reads an unpinned file.
    """
    build = CatalogueBuild()
    seen: set[str] = set()

    for row in read_rows(SOURCE_ROLE, SOURCE_FILE):
        build.rows_read += 1

        sku = _sku_for((row.get("pid") or "").strip())
        if sku is None:
            build.drop("unparseable_pid")
            continue
        if sku in seen:
            # Never coerced into a second SKU. Two products sharing a SKU would
            # make a cart's line items ambiguous and the substitution class
            # unfalsifiable.
            build.drop("duplicate_sku")
            continue

        top = _top_category((row.get("product_category_tree") or "").strip())
        if top is None:
            build.drop("unparseable_category")
            continue
        category = CATEGORY_MAP.get(top)
        if category is None:
            build.drop("category_outside_vocabulary")
            continue

        paise = _paise(row.get("retail_price", ""))
        if paise is None:
            build.drop("unparseable_price")
            continue
        if paise < MIN_PAISE:
            build.drop("price_below_floor")
            continue
        if paise > MAX_PAISE:
            build.drop("price_above_ceiling")
            continue

        name = _clean(row.get("product_name", ""))
        if not name:
            build.drop("missing_name")
            continue
        description = _clean(row.get("description", ""))
        if len(description) < 40:
            # A product page with no prose on it is a page an attack has
            # nothing to hide inside, and the surface being measured here is
            # prose.
            build.drop("description_too_short")
            continue

        seen.add(sku)
        build.products.append(
            Product(
                sku=sku,
                name=name,
                unit_amount=paise,
                category=category,
                description=description,
                brand=_clean(row.get("brand", "")) or "unbranded",
                source_pid=row["pid"],
            )
        )
        if limit is not None and len(build.products) >= limit:
            break

    build.products.sort(key=lambda p: p.sku)
    return build
