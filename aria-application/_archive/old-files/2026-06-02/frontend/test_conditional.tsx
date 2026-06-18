export function Test({ inv }: { inv: unknown }) {
  return (
    <div>
      {inv ? (
        <div />
      ) : null}
    </div>
  );
}
