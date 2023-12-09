#import "commons.typ": *

#let project(title: "", subtitle: "HEIG-VD - CAA", authors: ("Christophe Roulin",), body) = {
  // Set the document's basic properties.
  set document(author: authors, title: title)
  set page(numbering: "1", number-align: center)
  set text(font: "New Computer Modern", lang: "en", size: 10pt)
  show math.equation: set text(weight: 400)
  set heading(numbering: "1.1")

  // Subtitle information.
  pad(
    x: 2em,
    align(center)[
      #block(text(weight: 400, 1em, subtitle))
    ],
  )
  
  // Title row.
  align(center)[
    #block(text(weight: 700, 1.75em, title))
  ]

  // Author informations.
  pad(
    bottom: 0.5em,
    x: 2em,
    grid(
      columns: (1fr,) * calc.min(3, authors.len()),
      gutter: 1em,
      ..authors.map(author => align(center, strong(author))),
    ),
  )

  // Main body.
  set par(justify: true)

  // Set link style
  show link: underline

  body
}