#let custom_block(body, color) = {
  align([#block(
    fill: color,
    inset: 5pt,
    radius: 7pt,
    breakable: false,
    [#body])], center)
}

#let error(body) = {
  custom_block(body, rgb(255, 20, 0, 100))
}

#let warning(body) = {
  custom_block(body, rgb(255, 168, 2, 100))
}

#let info(body) = {
  custom_block(body, rgb(102, 163, 255, 100))
}