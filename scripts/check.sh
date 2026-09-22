#!/bin/sh
set -eu
flutter pub get
dart format lib test
git diff --exit-code -- lib test
flutter analyze
flutter test
flutter build web
