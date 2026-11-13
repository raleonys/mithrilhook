# MithrilHook visual and technical identity

The canonical name is **MithrilHook**. The logo is a silver M formed from
inward-curving hooks, enclosing a narrow ice-blue crystal and protective crest.
A circular luminous halo, three four-point stars, fine ornamental rules and
engraved Roman serif lettering connect it to the approved library family.

The approved master is `resources/branding/mithrilhook.png`, a 1536 x 1024 RGBA
PNG. Its emblem and ornaments have the approved five-pixel horizontal alignment
adjustment; the wordmark and original rendered details are preserved without
generative redrawing. The source-artwork hash and adjustment are recorded in
`metadata/BRANDING.json`. Preserve its
aspect ratio, wordmark, clear margins and color treatment. Do not stretch,
recolor or place competing text over the emblem. This master is raster artwork;
no editable vector master or separately drawn small icon is included.

The palette uses platinum silver, ice blue and deep steel shadows. Guideline
colors are `#DCE6EF`, `#9BCBEB`, `#E8F5FF` and `#10243B`; the rendered metallic
artwork contains additional shades and highlights.

Public names are:

| Surface | Identity |
| --- | --- |
| Repository and binary stem | `mithrilhook` |
| Public header | `MithrilHook.h` |
| Public API prefix | `MTH_` |
| CMake package | `MithrilHook` |
| CMake target | `MithrilHook::mithrilhook` |
| DLL product name | `MithrilHook` |

The installed logo is under `share/mithrilhook/branding`; this guide is under
`share/mithrilhook/doc`, using the configured CMake data directory. The installed
license directory retains the GPL distribution license and upstream notices.

Brand artwork is included in the GPL-3.0-only fork distribution. References to
MinHook, HDE, SAFE-FREEZE and Citrine in copyright, licensing, source provenance
and API comparisons identify inherited material; they are not active product
branding and must not be erased to imply independent authorship.
