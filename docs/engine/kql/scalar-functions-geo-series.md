# Scalar functions: `series_*`, `geo_*`, `convert_*`

These families appear on Microsoft Learn and are named or summarized in [`scalar-functions.md`](scalar-functions.md), but are **almost entirely absent** from [`catalogs/kql/core/functions.toml`](../../catalogs/kql/core/functions.toml).

Primary Learn hubs:

- [Scalar functions](https://learn.microsoft.com/kusto/query/scalar-functions)
- Series / geospatial sections of the scalar index (same hub)

Detection validity: **Yes** where Azure Monitor exposes the function; uncommon in classic scheduled analytics, more common in hunting / notebooks / ADX.

**Catalog today:** only `geo_info_from_ip_address` from these families; **0** `series_*`; **0** `convert_*`.

**Learn-vs-catalog gap: 111 scalars** (52 `geo_*` + 51 `series_*` + 8 `convert_*`).

---

## Unit conversion (`convert_*`) — 8

| Name |
| --- |
| `convert_angle` |
| `convert_energy` |
| `convert_force` |
| `convert_length` |
| `convert_mass` |
| `convert_speed` |
| `convert_temperature` |
| `convert_volume` |

Citation example: [convert_length](https://learn.microsoft.com/kusto/query/convert-length-function).

---

## Series element-wise — 23

`series_abs`, `series_acos`, `series_add`, `series_asin`, `series_atan`, `series_ceiling`, `series_cos`, `series_divide`, `series_equals`, `series_exp`, `series_floor`, `series_greater`, `series_greater_equals`, `series_less`, `series_less_equals`, `series_log`, `series_multiply`, `series_not_equals`, `series_pow`, `series_sign`, `series_sin`, `series_subtract`, `series_tan`

## Series processing — 28

`series_cosine_similarity`, `series_decompose`, `series_decompose_anomalies`, `series_decompose_forecast`, `series_dot_product`, `series_fill_backward`, `series_fill_const`, `series_fill_forward`, `series_fill_linear`, `series_fft`, `series_fir`, `series_fit_2lines`, `series_fit_2lines_dynamic`, `series_fit_line`, `series_fit_line_dynamic`, `series_fit_poly`, `series_ifft`, `series_iir`, `series_magnitude`, `series_outliers`, `series_pearson_correlation`, `series_periods_detect`, `series_periods_validate`, `series_product`, `series_seasonal`, `series_stats`, `series_stats_dynamic`, `series_sum`

**Series total: 51.**

---

## Geospatial (`geo_*`) — 52 missing (+ 1 present)

### Already in catalog

- `geo_info_from_ip_address`

### Missing from catalog (Learn scalar index)

`geo_angle`, `geo_azimuth`, `geo_closest_point_on_line`, `geo_closest_point_on_polygon`, `geo_distance_2points`, `geo_distance_point_to_line`, `geo_distance_point_to_polygon`, `geo_from_wkt`, `geo_geohash_neighbors`, `geo_geohash_to_central_point`, `geo_geohash_to_polygon`, `geo_h3cell_children`, `geo_h3cell_level`, `geo_h3cell_neighbors`, `geo_h3cell_parent`, `geo_h3cell_rings`, `geo_h3cell_to_central_point`, `geo_h3cell_to_polygon`, `geo_intersection_2lines`, `geo_intersection_2polygons`, `geo_intersection_line_with_polygon`, `geo_intersects_2lines`, `geo_intersects_2polygons`, `geo_intersects_line_with_polygon`, `geo_line_buffer`, `geo_line_centroid`, `geo_line_densify`, `geo_line_interpolate_point`, `geo_line_length`, `geo_line_locate_point`, `geo_line_simplify`, `geo_line_to_s2cells`, `geo_point_buffer`, `geo_point_in_circle`, `geo_point_in_polygon`, `geo_point_to_geohash`, `geo_point_to_h3cell`, `geo_point_to_s2cell`, `geo_polygon_area`, `geo_polygon_buffer`, `geo_polygon_centroid`, `geo_polygon_densify`, `geo_polygon_perimeter`, `geo_polygon_simplify`, `geo_polygon_to_h3cells`, `geo_polygon_to_s2cells`, `geo_s2cell_neighbors`, `geo_s2cell_to_central_point`, `geo_s2cell_to_polygon`, `geo_simplify_polygons_array`, `geo_union_lines_array`, `geo_union_polygons_array`

---

## Backfill note

Adding these **111** names to `functions.toml` with short `docs` + Learn `citation` (`kind = "scalar"`) closes the main remaining function-catalog gap for completion/hover.
