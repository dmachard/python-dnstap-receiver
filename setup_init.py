import argparse
import jinja2


def init_setup(pkgversion):
    if pkgversion.startswith("v"):
        pkgversion = pkgversion[1:]

    # open the jinja2 template
    with open("setup_template.j2") as f:
        setup_tpl = f.read()

    # write setp
    j2 = jinja2.Template(setup_tpl)
    with open("setup.py", "w") as f:
        f.write(j2.render( {"pkg_version": pkgversion} ))

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('pkgversion', type=str)

    # read argument, expected package version
    args = parser.parse_args()

    # create the python setup file
    init_setup(args.pkgversion)