# drand-draw-action

A github action for drawing items from a file randomly.

## configuration

- `inputDir`
The directory of files you wish to choose randomly from. The default is `.`
- `outputDir`
The directory where you wish the randomly selected output to go. The default is `.`
- `outputPrefix`
Files in the `outputDir` will be prefixed with this. Useful so you don't overwrite files if you're using the same directory for input and output.. The default is `draw-`
- `count`
The number of items to draw from each file
- `drandURL`
The drand endpoint you wish to use for the draw. The default is `https://api.drand.sh`

## contributing

There is a husky pre-commit hook that runs the build. In order to function as a github action, the `index.js` build artifact must be built and in the repo root directory