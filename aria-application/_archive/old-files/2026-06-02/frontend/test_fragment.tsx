export function Test({ x }: { x: unknown }) {
  return (
    <>
      <div />
      {x && <div />}
    </>
  );
}
