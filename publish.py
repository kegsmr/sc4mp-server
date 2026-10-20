import sys

from sc4mpserver import SC4MP_VERSION, SC4MP_GITHUB_REPO
from core.util import (
    get_current_git_branch,
    get_release_asset_path,
    publish_release,
)


repo = SC4MP_GITHUB_REPO
token = sys.argv[1]
version = SC4MP_VERSION
assets = [
    ("setupbuilds", f"sc4mp-server-installer-windows-v{version}"),
    ("builds", f"sc4mp-server-windows-64-v{version}"),
    ("builds", f"sc4mp-server-windows-32-v{version}"),
]


target = get_current_git_branch()

if target == "main":
    name = f"Patch {version}"
    body = "This is a patch that fixes some things."
    prerelease = False
elif target == "feature":
    name = f"Preview {version}"
    body = "\n\n".join([
        "This is a pre-release introducing new features from the next "
        "update, but also likely many bugs.",
        "If you encounter any issues, please report them on GitHub or in the "
        "SC4MP Discord.",
        "Thank you for playing on the SC4MP network, and stay tuned for "
        "further updates!",
    ])
    prerelease = True
else:
    raise Exception(
        "Releases can only be published from the `main` or `feature` branch."
    )

# Use the newest file for each asset, and skip the ones that weren't built
asset_paths = []
for directory, prefix in assets:
    asset_path = get_release_asset_path(directory, prefix)
    if asset_path is not None:
        asset_paths.append(asset_path)
assets = asset_paths

publish_release(
    repo=repo,
    token=token,
    version=version,
    target=target,
    name=name,
    body=body,
    assets=assets,
    prerelease=prerelease,
)
